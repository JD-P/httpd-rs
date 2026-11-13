#!/usr/bin/env python3
"""Differential cache-hit benchmark: httpd-rs vs. Apache mod_cache.

Both servers serve the same tree, warm the same `/cached/` entries, and are
verified to return a cache HIT before timing.  The harness also measures a
non-cached static file as the per-request baseline.

Usage:
    cargo build --release -p httpd-rs
    python3 bench/cache_bench.py --quick
    python3 bench/cache_bench.py

Results are written under bench/results/ and appended to
bench/CACHE_RESULTS.md.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench"
RUN = Path("/tmp/httpd-rs-cache-bench")
APACHE = shutil.which("apache2") or "/usr/sbin/apache2"
HTTPD_RS = ROOT / "target" / "release" / "httpd-rs"
WRK = shutil.which("wrk")
MODULES = Path("/usr/lib/apache2/modules")

AP_PORT, VP_PORT = 18082, 18083
SCENARIOS = [
    ("cache HIT 1.1KB", "/cached/hello.txt", True, 64),
    ("cache HIT 10KB", "/cached/10k.bin", True, 64),
    ("cache HIT 1MB", "/cached/1m.bin", True, 16),
    ("static 1.1KB", "/hello.txt", False, 64),
]


def make_tree() -> None:
    shutil.rmtree(RUN, ignore_errors=True)
    www = RUN / "www"
    (www / "cached").mkdir(parents=True)
    (RUN / "logs").mkdir()
    (www / "hello.txt").write_bytes(b"hello world\n" * 100)
    (www / "cached" / "hello.txt").write_bytes(b"hello world\n" * 100)
    (www / "cached" / "10k.bin").write_bytes(b"x" * (10 * 1024))
    (www / "cached" / "1m.bin").write_bytes(b"y" * (1024 * 1024))
    for path in www.rglob("*"):
        os.chmod(path, 0o644 if path.is_file() else 0o755)
    os.chmod(www, 0o755)
    os.chmod(RUN / "logs", 0o777)
    for name in ("apache", "httpd-rs", "apache-cache", "httpd-rs-cache"):
        (RUN / name).mkdir()
        os.chmod(RUN / name, 0o777)


def common_server_config(port: int, server_root: Path, cache_root: Path) -> str:
    return f"""ServerRoot "{server_root}"
Listen {port}
User www-data
Group www-data
PidFile "{RUN}/logs/pid-{port}"
ErrorLog "{RUN}/logs/error-{port}.log"
LogLevel warn
ServerName bench.local
Timeout 60
KeepAlive On
MaxKeepAliveRequests 1000
KeepAliveTimeout 5
DocumentRoot "{RUN}/www"
CacheRoot "{cache_root}"
CacheEnable disk /cached/
CacheHeader On
CacheIgnoreNoLastMod On
CacheDefaultExpire 3600
CacheMaxExpire 3600
CacheMaxFileSize 2097152
<Directory />
    Require all denied
</Directory>
<Directory "{RUN}/www">
    Options FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
TypesConfig /etc/mime.types
DirectoryIndex index.html
CustomLog /dev/null common
"""


def apache_config(port: int) -> Path:
    path = RUN / f"apache-{port}.conf"
    modules = "\n".join(
        f"LoadModule {name}_module {MODULES}/mod_{name}.so"
        for name in (
            "mpm_event",
            "mime",
            "dir",
            "authz_core",
            "authz_host",
            "cache",
            "cache_disk",
            "headers",
        )
    )
    path.write_text(
        modules
        + "\n"
        + common_server_config(port, RUN / "apache", RUN / "apache-cache")
        + '<Directory "/tmp/httpd-rs-cache-bench/www">\n'
        + '    Header set Cache-Control "max-age=600"\n'
        + "</Directory>\n"
    )
    return path


def httpd_rs_config(port: int) -> Path:
    path = RUN / f"httpd-rs-{port}.conf"
    path.write_text(common_server_config(port, RUN, RUN / "httpd-rs-cache"))
    return path


def wait_port(port: int, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def start(cmd: list[str], log: Path):
    handle = open(log, "ab")
    proc = subprocess.Popen(
        cmd, stdout=handle, stderr=subprocess.STDOUT, start_new_session=True
    )
    return proc, handle


def stop(proc) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)


def get(port: int, path: str):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    response = conn.getresponse()
    body = response.read()
    headers = {name.lower(): value for name, value in response.getheaders()}
    status = response.status
    conn.close()
    return status, headers, body


def warm_cache(port: int, path: str, label: str) -> None:
    cache = ""
    for _ in range(8):
        status, headers, _ = get(port, path)
        if status != 200:
            raise SystemExit(f"{label}: warm request returned {status}")
        cache = headers.get("x-cache", "")
        if "hit" in cache.lower():
            return
        time.sleep(0.1)
    raise SystemExit(
        f"{label}: cache did not warm (X-Cache={cache!r}); refusing to "
        "benchmark a cache miss"
    )


def parse_latency(value: float, unit: str) -> float:
    if unit == "us":
        return value / 1000.0
    if unit == "s":
        return value * 1000.0
    return value


def run_wrk(url: str, duration: float, concurrency: int) -> dict:
    threads = 4 if concurrency >= 50 else 2
    output = subprocess.run(
        [
            WRK,
            f"-t{threads}",
            f"-c{concurrency}",
            f"-d{duration:g}s",
            "--latency",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    text = output.stdout + output.stderr
    rps = re.search(r"Requests/sec:\s+([0-9.]+)", text)
    latency = re.search(r"Latency\s+([0-9.]+)(us|ms|s)\s+", text)
    p99 = re.search(r"^\s*99%\s+([0-9.]+)(us|ms|s)\s*$", text, re.MULTILINE)
    return {
        "rps": float(rps.group(1)) if rps else None,
        "mean_ms": (
            parse_latency(float(latency.group(1)), latency.group(2))
            if latency
            else None
        ),
        "p99_ms": parse_latency(float(p99.group(1)), p99.group(2)) if p99 else None,
        "raw": text if output.returncode != 0 else "",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--duration", type=float, default=0)
    parser.add_argument("--samples", type=int, default=0)
    parser.add_argument("--concurrency", type=int, default=0)
    args = parser.parse_args()

    if not WRK:
        raise SystemExit("wrk is required")
    if not HTTPD_RS.exists():
        raise SystemExit(f"{HTTPD_RS} missing; run cargo build --release first")
    if not APACHE or not MODULES.exists():
        raise SystemExit("apache2 and its module directory are required")

    duration = args.duration or (1.0 if args.quick else 3.0)
    samples = args.samples or (1 if args.quick else 3)
    # The 1 MB cache case is slow and less useful for trend runs.
    scenarios = SCENARIOS[:2] + SCENARIOS[3:] if args.quick else SCENARIOS

    make_tree()
    apache, apache_log = start(
        [APACHE, "-f", str(apache_config(AP_PORT)), "-DFOREGROUND"],
        RUN / "logs" / "apache.out",
    )
    httpd_rs, httpd_rs_log = start(
        [str(HTTPD_RS), "-f", str(httpd_rs_config(VP_PORT)), "-DFOREGROUND"],
        RUN / "logs" / "httpd-rs.out",
    )
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "wrk",
        "duration_s": duration,
        "samples": samples,
        "scenarios": [],
    }
    try:
        if not wait_port(AP_PORT) or not wait_port(VP_PORT):
            print((RUN / "logs" / "apache.out").read_text()[-4000:])
            print((RUN / "logs" / "httpd-rs.out").read_text()[-4000:])
            raise SystemExit("server failed to start")

        print(
            f"{'scenario':24} {'server':9} {'req/s':>10} {'mean ms':>9} "
            f"{'p99 ms':>8}"
        )
        for label, path, cached, default_conc in scenarios:
            concurrency = args.concurrency or default_conc
            row = {
                "name": label,
                "path": path,
                "concurrency": concurrency,
                "servers": {},
            }
            for server, port in (("apache", AP_PORT), ("httpd-rs", VP_PORT)):
                if cached:
                    warm_cache(port, path, f"{server} {label}")
                url = f"http://127.0.0.1:{port}{path}"
                run_wrk(url, max(0.5, duration / 2), concurrency)
                samples_out = sorted(
                    (run_wrk(url, duration, concurrency) for _ in range(samples)),
                    key=lambda value: value["rps"] or 0,
                )
                best = samples_out[len(samples_out) // 2]
                row["servers"][server] = best
                print(
                    f"{label:24} {server:9} {best['rps'] or 0:10.0f} "
                    f"{best['mean_ms'] or 0:9.2f} {best['p99_ms'] or 0:8.1f}",
                    flush=True,
                )
                if best["raw"]:
                    print(f"  !! {server} {label}:\n{best['raw'][-1500:]}")
            apache_rps = row["servers"]["apache"]["rps"] or 0
            httpd_rs_rps = row["servers"]["httpd-rs"]["rps"] or 0
            row["ratio"] = httpd_rs_rps / apache_rps if apache_rps else None
            print(f"{'  httpd-rs/apache ratio':24} {'':9} {row['ratio'] or 0:10.2f}x")
            results["scenarios"].append(row)

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        (BENCH / "results").mkdir(exist_ok=True)
        (BENCH / "results" / f"cache-{stamp}.json").write_text(
            json.dumps(results, indent=2)
        )
        lines = [
            f"\n## {results['timestamp']}\n",
            "| scenario | Apache req/s | httpd-rs req/s | ratio | mean ms (v) | p99 ms (v) |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        for row in results["scenarios"]:
            apache_rps = row["servers"]["apache"]["rps"] or 0
            httpd_rs_rps = row["servers"]["httpd-rs"]["rps"] or 0
            lines.append(
                f"| {row['name']} | {apache_rps:.0f} | {httpd_rs_rps:.0f} | "
                f"{row['ratio'] or 0:.2f}x | "
                f"{row['servers']['httpd-rs']['mean_ms'] or 0:.2f} | "
                f"{row['servers']['httpd-rs']['p99_ms'] or 0:.1f} |"
            )
        with open(BENCH / "CACHE_RESULTS.md", "a") as handle:
            handle.write("\n".join(lines) + "\n")
        print(f"\nresults: {BENCH / 'results' / f'cache-{stamp}.json'}")
    finally:
        stop(httpd_rs)
        stop(apache)
        apache_log.close()
        httpd_rs_log.close()


if __name__ == "__main__":
    main()
