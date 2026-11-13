#!/usr/bin/env python3
"""Differential benchmark: httpd-rs vs. the real Apache httpd.

Both servers serve the exact same DocumentRoot on the loopback interface with
identical keep-alive settings.  Results are written to bench/results/ and a
summary is appended to bench/RESULTS.md.

Usage: python3 bench/bench.py [--quick] [--requests N] [--concurrency N]

wrk is used when available (HTTP/1.1, reliable keep-alive under load); ab is a
fallback.  wrk runs are duration based, so --requests only affects the ab
fallback.
"""

import argparse
import grp
import json
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench"
RUN = Path("/tmp/httpd-rs-bench")
APACHE = os.environ.get("APACHE") or shutil.which("apache2") or "/usr/sbin/apache2"
HTTPD_RS = Path(os.environ.get("HTTPD_RS", ROOT / "target" / "release" / "httpd-rs"))
AB = os.environ.get("AB") or shutil.which("ab")
WRK = os.environ.get("WRK") or shutil.which("wrk")
APACHE_MODDIR = Path(os.environ.get("APACHE_MODDIR", "/usr/lib/apache2/modules"))
BENCH_USER = "www-data" if os.geteuid() == 0 else pwd.getpwuid(os.geteuid()).pw_name
BENCH_GROUP = "www-data" if os.geteuid() == 0 else grp.getgrgid(os.getegid()).gr_name


def make_tree():
    www = RUN / "www"
    (www / "small").mkdir(parents=True, exist_ok=True)
    (www / "large").mkdir(parents=True, exist_ok=True)
    (www / "index.html").write_bytes(
        b"<!doctype html><html><body><h1>httpd-rs benchmark</h1></body></html>\n"
    )
    (www / "hello.txt").write_bytes(b"hello world\n" * 100)
    (www / "small" / "10k.bin").write_bytes(os.urandom(10 * 1024))
    if not (www / "large" / "1m.bin").exists():
        (www / "large" / "1m.bin").write_bytes(os.urandom(1024 * 1024))
    for p in www.rglob("*"):
        os.chmod(p, 0o644 if p.is_file() else 0o755)
    os.chmod(www, 0o755)


def apache_config(port):
    d = RUN / "apache"
    (d / "logs").mkdir(parents=True, exist_ok=True)
    cfg = d / "httpd.conf"
    cfg.write_text(
        f"""ServerRoot "{d}"
Listen {port}
User {BENCH_USER}
Group {BENCH_GROUP}
PidFile {d}/logs/httpd.pid
ErrorLog {d}/logs/error.log
LogLevel warn
ServerName bench.local
Timeout 60
KeepAlive On
MaxKeepAliveRequests 10000
KeepAliveTimeout 5
DocumentRoot "{RUN}/www"
<Directory />
    Require all denied
</Directory>
<Directory "{RUN}/www">
    Options FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
LoadModule mpm_event_module {APACHE_MODDIR}/mod_mpm_event.so
LoadModule mime_module {APACHE_MODDIR}/mod_mime.so
LoadModule dir_module {APACHE_MODDIR}/mod_dir.so
LoadModule alias_module {APACHE_MODDIR}/mod_alias.so
LoadModule authz_core_module {APACHE_MODDIR}/mod_authz_core.so
LoadModule authz_host_module {APACHE_MODDIR}/mod_authz_host.so
TypesConfig /etc/mime.types
DirectoryIndex index.html
LogFormat "%h %l %u %t \\"%r\\" %>s %O" common
CustomLog /dev/null common
"""
    )
    return cfg


def httpd_rs_config(port):
    d = RUN / "httpd-rs"
    (d / "logs").mkdir(parents=True, exist_ok=True)
    cfg = d / "httpd.conf"
    cfg.write_text(
        f"""ServerRoot "{d}"
Listen {port}
User {BENCH_USER}
Group {BENCH_GROUP}
PidFile {d}/logs/httpd.pid
ErrorLog {d}/logs/error.log
LogLevel warn
ServerName bench.local
Timeout 60
KeepAlive On
MaxKeepAliveRequests 10000
KeepAliveTimeout 5
DocumentRoot "{RUN}/www"
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
LogFormat "%h %l %u %t \\"%r\\" %>s %O" common
CustomLog /dev/null common
"""
    )
    return cfg


def wait_port(port, timeout=10):
    import socket

    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def start(cmd, log):
    f = open(log, "ab")
    p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
    return p, f


def parse_latency(value, unit):
    value = float(value)
    if unit == "us":
        return value / 1000.0
    if unit == "s":
        return value * 1000.0
    return value


def run_wrk(url, duration, concurrency):
    threads = 4 if concurrency >= 50 else 2
    cmd = [
        WRK,
        f"-t{threads}",
        f"-c{concurrency}",
        f"-d{duration:g}s",
        "--latency",
        url,
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    text = out.stdout + out.stderr

    def grab(pat, cast=float):
        m = re.search(pat, text)
        return cast(m.group(1)) if m else None

    mean_ms = None
    m = re.search(r"Latency\s+([0-9.]+)(us|ms|s)\s+", text)
    if m:
        mean_ms = parse_latency(m.group(1), m.group(2))
    p99_ms = None
    m = re.search(r"^\s*99%\s+([0-9.]+)(us|ms|s)\s*$", text, re.MULTILINE)
    if m:
        p99_ms = parse_latency(m.group(1), m.group(2))
    transferred_kbps = None
    m = re.search(r"Transfer/sec:\s+([0-9.]+)([KMGT]?B)", text)
    if m:
        scale = {"B": 1 / 1024, "KB": 1, "MB": 1024, "GB": 1024 * 1024, "TB": 1024**3}
        transferred_kbps = float(m.group(1)) * scale[m.group(2)]
    err = re.search(
        r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", text
    )
    errors = {
        "connect": int(err.group(1)),
        "read": int(err.group(2)),
        "write": int(err.group(3)),
        "timeout": int(err.group(4)),
    } if err else {"connect": 0, "read": 0, "write": 0, "timeout": 0}
    return {
        "rps": grab(r"Requests/sec:\s+([0-9.]+)"),
        "mean_ms": mean_ms,
        "p99_ms": p99_ms,
        "transferred_kbps": transferred_kbps,
        "failed": 0,
        "non2xx": grab(r"Non-2xx or 3xx responses:\s+(\d+)", int) or 0,
        "socket_errors": errors,
        "raw": text if out.returncode != 0 else "",
    }


def run_ab(url, requests, concurrency):
    cmd = [AB, "-q", "-k", "-n", str(requests), "-c", str(concurrency), url]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    text = out.stdout + out.stderr
    def grab(pat, cast=float):
        m = re.search(pat, text)
        return cast(m.group(1)) if m else None
    return {
        "rps": grab(r"Requests per second:\s+([0-9.]+)"),
        "mean_ms": grab(r"Time per request:\s+([0-9.]+)\s+\[ms\] \(mean\)"),
        "p50_ms": grab(r"50%\s+([0-9]+)"),
        "p95_ms": grab(r"95%\s+([0-9]+)"),
        "p99_ms": grab(r"99%\s+([0-9]+)"),
        "failed": grab(r"Failed requests:\s+([0-9]+)", int),
        "non2xx": grab(r"Non-2xx responses:\s+([0-9]+)", int),
        "transferred_kbps": grab(r"Transfer rate:\s+([0-9.]+)"),
        "raw": text if out.returncode != 0 else "",
    }


def stop(p):
    if p.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        p.wait()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--requests", type=int, default=0)
    ap.add_argument("--concurrency", type=int, default=0)
    ap.add_argument("--duration", type=float, default=0)
    args = ap.parse_args()
    if not WRK and not AB:
        sys.exit("wrk or apache2-utils (ab) is required")
    if not HTTPD_RS.exists():
        sys.exit(f"{HTTPD_RS} missing; run cargo build --release first")

    make_tree()
    apache_port, httpd_rs_port = 8080, 8081
    acfg = apache_config(apache_port)
    vcfg = httpd_rs_config(httpd_rs_port)
    (RUN / "logs").mkdir(exist_ok=True)
    apache, alog = start([APACHE, "-f", str(acfg), "-DFOREGROUND"], RUN / "logs" / "apache.out")
    vap, vlog = start([str(HTTPD_RS), "-f", str(vcfg), "-DFOREGROUND"], RUN / "logs" / "httpd-rs.out")
    try:
        if not wait_port(apache_port) or not wait_port(httpd_rs_port):
            print(open(RUN / "logs" / "apache.out").read())
            print(open(RUN / "logs" / "httpd-rs.out").read())
            sys.exit("server failed to start")
        scenarios = [
            ("index.html (small, keepalive)", "/index.html"),
            ("hello.txt (1.1KB, keepalive)", "/hello.txt"),
            ("10k.bin (10KB, keepalive)", "/small/10k.bin"),
            ("1m.bin (1MB, keepalive)", "/large/1m.bin"),
        ]
        if args.quick:
            # wrk opens its cohort simultaneously from one loopback identity.
            # Stay within httpd-rs's per-client pending-connection ceiling so
            # this measures serving rather than overload rejection.
            tests = [(n, p, 3000, 8) for n, p in scenarios[:3]] + [
                (scenarios[3][0], scenarios[3][1], 300, 8)
            ]
        else:
            req = args.requests or 20000
            conc = args.concurrency or 8
            tests = [(n, p, req, conc) for n, p in scenarios[:3]] + [
                (
                    scenarios[3][0],
                    scenarios[3][1],
                    max(500, req // 10),
                    max(1, min(8, conc)),
                )
            ]
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": "wrk" if WRK else "ab",
            "scenarios": [],
        }
        print(f"{'scenario':38} {'server':10} {'req/s':>10} {'mean ms':>9} {'p99 ms':>8} {'MB/s':>8}")
        for name, path, req, conc in tests:
            row = {"name": name, "path": path, "requests": req, "concurrency": conc, "servers": {}}
            endpoints = (("apache", apache_port), ("httpd-rs", httpd_rs_port))
            collected = {server: [] for server, _ in endpoints}
            duration = args.duration or (1.0 if args.quick else 3.0)
            for _, port in endpoints:
                url = f"http://127.0.0.1:{port}{path}"
                if WRK:
                    run_wrk(url, 1, conc)
                else:
                    run_ab(url, max(200, req // 20), conc)
                # Let the server observe EOF and retire the warm-up cohort.
                time.sleep(0.25)
            # Alternate server order so shared-host drift cannot systematically
            # favor whichever implementation happens to run first.
            for sample in range(3):
                order = endpoints if sample % 2 == 0 else tuple(reversed(endpoints))
                for server, port in order:
                    url = f"http://127.0.0.1:{port}{path}"
                    value = run_wrk(url, duration, conc) if WRK else run_ab(url, req, conc)
                    collected[server].append(value)
                    time.sleep(0.25)
            for server, _ in endpoints:
                samples = collected[server]
                samples.sort(key=lambda r: r["rps"] or 0)
                best = samples[len(samples) // 2]
                row["servers"][server] = best
                print(
                    f"{name:38} {server:10} {best['rps'] or 0:10.0f} "
                    f"{best['mean_ms'] or 0:9.2f} {best['p99_ms'] or 0:8.0f} "
                    f"{(best['transferred_kbps'] or 0)/1024:8.1f}"
                )
                if best["failed"] or best["non2xx"]:
                    print(f"  !! failed={best['failed']} non2xx={best['non2xx']}")
                    if best["raw"]:
                        print(best["raw"][-2000:])
                errs = best.get("socket_errors") or {}
                if any(errs.values()):
                    print(f"  !! socket errors={errs}")
            a = row["servers"]["apache"]["rps"] or 0
            v = row["servers"]["httpd-rs"]["rps"] or 0
            row["ratio"] = (v / a) if a else None
            print(f"{'  httpd-rs/apache ratio':38} {'':10} {row['ratio'] or 0:10.2f}x")
            results["scenarios"].append(row)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        (BENCH / "results").mkdir(parents=True, exist_ok=True)
        out = BENCH / "results" / f"{stamp}.json"
        out.write_text(json.dumps(results, indent=2))
        lines = [f"\n## {results['timestamp']}\n", "| scenario | apache req/s | httpd-rs req/s | ratio | mean ms (v) | p99 ms (v) |", "|---|---:|---:|---:|---:|---:|"]
        for row in results["scenarios"]:
            a = row["servers"]["apache"]["rps"] or 0
            v = row["servers"]["httpd-rs"]["rps"] or 0
            lines.append(
                f"| {row['name']} | {a:.0f} | {v:.0f} | {row['ratio'] or 0:.2f}x | "
                f"{row['servers']['httpd-rs']['mean_ms'] or 0:.2f} | {row['servers']['httpd-rs']['p99_ms'] or 0:.0f} |"
            )
        with open(BENCH / "RESULTS.md", "a") as f:
            f.write("\n".join(lines) + "\n")
        print(f"\nresults: {out}")
    finally:
        stop(vap)
        stop(apache)
        alog.close()
        vlog.close()


if __name__ == "__main__":
    main()
