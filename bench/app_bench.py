#!/usr/bin/env python3
"""PHP-FPM and Gunicorn application benchmark against Apache and vapache.

This fixture exercises the production-shaped dynamic paths rather than the
native-CGI and mock-proxy paths in feature_bench.py:

  /index.php  -> PHP-FPM over FastCGI (Unix socket)
  /app/hello  -> Gunicorn/WSGI over HTTP proxy

Both servers share the same upstream PHP-FPM pool and Gunicorn workers.  Access
logs are disabled so the comparison measures the front-end/upstream hop.

Usage:
    python3 bench/app_bench.py
    python3 bench/app_bench.py --quick
    python3 bench/app_bench.py --only php
    python3 bench/app_bench.py --only gunicorn --keep

Requires: apache2, target/release/vapached, wrk and php-fpm. Gunicorn is
required only when its scenario is selected.
"""

import argparse
import grp
import json
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench"
DEFAULT_RUN = "/run/vapache-app-bench" if os.geteuid() == 0 else "/tmp/vapache-app-bench"
RUN = Path(os.environ.get("VAPACHE_APP_BENCH_RUN", DEFAULT_RUN))
APACHE = os.environ.get("APACHE") or shutil.which("apache2") or "/usr/sbin/apache2"
VAPACHED = Path(os.environ.get("VAPACHED", ROOT / "target" / "release" / "vapached"))
WRK = os.environ.get("WRK") or shutil.which("wrk")
GUNICORN = os.environ.get("GUNICORN") or shutil.which("gunicorn")
PHP_FPM = os.environ.get("PHP_FPM") or shutil.which("php-fpm")
if PHP_FPM is None:
    candidates = sorted(Path("/usr/sbin").glob("php-fpm*"))
    PHP_FPM = str(candidates[0]) if candidates else None
APACHE_MODDIR = Path(os.environ.get("APACHE_MODDIR", "/usr/lib/apache2/modules"))
BENCH_USER = "www-data" if os.geteuid() == 0 else pwd.getpwuid(os.geteuid()).pw_name
BENCH_GROUP = "www-data" if os.geteuid() == 0 else grp.getgrgid(os.getegid()).gr_name
BACKEND_UID = 33 if os.geteuid() == 0 else os.geteuid()

AP_PORT, VP_PORT = 19080, 19081
GUNICORN_PORT = 19090

SCENARIOS = [
    # Vapache admits at most eight concurrent dynamic requests from one client.
    # Loopback is one identity, so a higher benchmark concurrency measures the
    # deliberate overload response rather than backend throughput.
    dict(name="PHP-FPM /index.php", path="/index.php", marker=b"php-fpm", conc=8),
    dict(name="Gunicorn /app/hello", path="/app/hello", marker=b"gunicorn", conc=8),
]


def die(msg):
    print(f"app_bench: {msg}", file=sys.stderr)
    raise SystemExit(2)


def check_tools(needs_gunicorn):
    missing = []
    if not Path(APACHE).exists() and shutil.which(APACHE) is None:
        missing.append("apache2")
    if not VAPACHED.exists():
        missing.append(str(VAPACHED.relative_to(ROOT)))
    if not WRK:
        missing.append("wrk")
    if not PHP_FPM:
        missing.append("php-fpm")
    if needs_gunicorn and not GUNICORN:
        missing.append("gunicorn")
    if missing:
        die("missing required tool(s): " + ", ".join(missing))


def make_fixture():
    shutil.rmtree(RUN, ignore_errors=True)
    for d in [
        RUN / "www",
        RUN / "wsgi",
        RUN / "fpm",
        RUN / "apache" / "logs",
        RUN / "vapache" / "logs",
    ]:
        d.mkdir(parents=True, exist_ok=True)
    shutil.copy2(BENCH / "php-app" / "index.php", RUN / "www" / "index.php")
    shutil.copy2(BENCH / "wsgi-app" / "app.py", RUN / "wsgi" / "app.py")
    for p in [RUN, RUN / "www", RUN / "wsgi", RUN / "fpm"]:
        os.chmod(p, 0o755)
    os.chmod(RUN / "www" / "index.php", 0o644)
    os.chmod(RUN / "wsgi" / "app.py", 0o644)


def write_fpm_config():
    cfg = RUN / "fpm" / "php-fpm.conf"
    is_root = os.geteuid() == 0
    owner = "user = www-data\ngroup = www-data\n" if is_root else ""
    listen_owner = (
        f"listen.owner = www-data\nlisten.group = www-data\n" if is_root else ""
    )
    cfg.write_text(
        f"""[global]
pid = {RUN}/fpm/php-fpm.pid
error_log = {RUN}/fpm/error.log
daemonize = no
[www]
{owner}listen = {RUN}/fpm/php.sock
{listen_owner}listen.mode = 0660
pm = static
pm.max_children = 32
catch_workers_output = yes
"""
    )
    return cfg


def wait_unix(path, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if Path(path).exists():
            return True
        time.sleep(0.05)
    return False


def wait_tcp(port, timeout=10):
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


def stop(p, f=None):
    if p is not None and p.poll() is None:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
    if f is not None:
        f.close()


def common_config_lines(port, docroot, php_socket, apache):
    modules = []
    if apache:
        moddir = APACHE_MODDIR
        modules = [
            f"LoadModule mpm_event_module {moddir}/mod_mpm_event.so",
            f"LoadModule authz_core_module {moddir}/mod_authz_core.so",
            f"LoadModule authz_host_module {moddir}/mod_authz_host.so",
            f"LoadModule proxy_module {moddir}/mod_proxy.so",
            f"LoadModule proxy_fcgi_module {moddir}/mod_proxy_fcgi.so",
            f"LoadModule proxy_http_module {moddir}/mod_proxy_http.so",
            f"LoadModule dir_module {moddir}/mod_dir.so",
        ]
    vapache_security = [] if apache else [
        "VapacheCapability FastCgi On",
        f"VapacheFastCGIStablePath On unix:{php_socket} {BACKEND_UID} {BACKEND_UID} 0",
    ]
    return "\n".join(
        modules
        + vapache_security
        + [
            f"Listen {port}",
            "ServerName app-bench.local",
            "Timeout 30",
            "KeepAlive On",
            "MaxKeepAliveRequests 1000",
            "KeepAliveTimeout 5",
            f"DocumentRoot \"{docroot}\"",
            "<Directory />",
            "    Require all denied",
            "</Directory>",
            f"<Directory \"{docroot}\">",
            "    Options FollowSymLinks",
            "    AllowOverride None",
            "    Require all granted",
            "</Directory>",
            f'ProxyPassMatch ^/(.*\\.php(/.*)?)$ "unix:{php_socket}|fcgi://localhost{docroot}/"',
            f"ProxyPass /app http://127.0.0.1:{GUNICORN_PORT}/",
            f"ProxyPassReverse /app http://127.0.0.1:{GUNICORN_PORT}/",
            "DirectoryIndex index.php",
        ]
    ) + "\n"


def write_server_configs():
    docroot = str(RUN / "www")
    php_socket = str(RUN / "fpm" / "php.sock")
    apache_cfg = RUN / "apache" / "httpd.conf"
    vapache_cfg = RUN / "vapache" / "httpd.conf"
    apache_cfg.write_text(
        f"""ServerRoot "{RUN}/apache"
PidFile "{RUN}/apache/logs/httpd.pid"
ErrorLog "{RUN}/apache/logs/error.log"
LogLevel warn
User {BENCH_USER}
Group {BENCH_GROUP}
"""
        + common_config_lines(AP_PORT, docroot, php_socket, True)
    )
    vapache_cfg.write_text(
        f"""ServerRoot "{RUN}/vapache"
PidFile "{RUN}/vapache/logs/httpd.pid"
ErrorLog "{RUN}/vapache/logs/error.log"
LogLevel warn
User {BENCH_USER}
Group {BENCH_GROUP}
"""
        + common_config_lines(VP_PORT, docroot, php_socket, False)
    )
    return apache_cfg, vapache_cfg


def probe(port, path, marker):
    import urllib.request

    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as r:
            body = r.read()
            return r.status, body, marker in body
    except Exception as e:
        return None, str(e).encode(), False


def parse_wrk(text):
    def num(pat, cast=float):
        m = re.search(pat, text)
        return cast(m.group(1)) if m else None

    ms = None
    m = re.search(r"Latency\s+([0-9.]+)(us|ms|s)\s+", text)
    if m:
        v = float(m.group(1))
        ms = v / 1000 if m.group(2) == "us" else v * 1000 if m.group(2) == "s" else v
    p99 = None
    m = re.search(r"^\s*99%\s+([0-9.]+)(us|ms|s)\s*$", text, re.MULTILINE)
    if m:
        v = float(m.group(1))
        p99 = v / 1000 if m.group(2) == "us" else v * 1000 if m.group(2) == "s" else v
    errors = re.search(
        r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", text
    )
    socket_errors = tuple(map(int, errors.groups())) if errors else (0, 0, 0, 0)
    return dict(
        rps=num(r"Requests/sec:\s+([0-9.]+)"),
        mean_ms=ms,
        p99_ms=p99,
        non2xx=num(r"Non-2xx or 3xx responses:\s+(\d+)", int) or 0,
        socket_errors=socket_errors,
        raw=text,
    )


def measure(port, path, duration, conc):
    url = f"http://127.0.0.1:{port}{path}"
    cmd = [WRK, "-t4", f"-c{conc}", f"-d{duration:g}s", "--latency", url]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return parse_wrk(out.stdout + out.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="1s samples, one run")
    ap.add_argument("--only", default=None, help="regex filter for PHP/Gunicorn scenarios")
    ap.add_argument("--keep", action="store_true", help="leave fixture and servers running")
    ap.add_argument("--duration", type=float, default=None)
    ap.add_argument("--samples", type=int, default=3)
    args = ap.parse_args()
    duration = args.duration or (1.0 if args.quick else 3.0)
    samples = 1 if args.quick else args.samples
    selected = [s for s in SCENARIOS if not args.only or re.search(args.only, s["name"], re.I)]
    if not selected:
        die("no scenarios matched --only")
    needs_gunicorn = any(s["marker"] == b"gunicorn" for s in selected)
    needs_php = any(s["marker"] == b"php-fpm" for s in selected)
    if (
        needs_php
        and os.geteuid() != 0
        and os.environ.get("VAPACHE_APP_BENCH_PREPARED_STABLE_PATH") != "1"
    ):
        die(
            "the secure PHP benchmark must run as root so its fixture can live "
            "under root-owned /run; alternatively pre-provision a stable path and "
            "set VAPACHE_APP_BENCH_RUN plus VAPACHE_APP_BENCH_PREPARED_STABLE_PATH=1"
        )
    check_tools(needs_gunicorn)

    make_fixture()
    fpm_cfg = write_fpm_config()
    apache_cfg, vapache_cfg = write_server_configs()

    fpm = gunicorn = apache = vapache = None
    fpm_log = gunicorn_log = apache_log = vapache_log = None
    try:
        fpm, fpm_log = start([PHP_FPM, "-F", "-y", str(fpm_cfg)], RUN / "fpm" / "stdout.log")
        if not wait_unix(RUN / "fpm" / "php.sock"):
            die("PHP-FPM did not create its socket")

        if needs_gunicorn:
            gunicorn, gunicorn_log = start(
                [
                    GUNICORN,
                    "--workers",
                    "8",
                    "--bind",
                    f"127.0.0.1:{GUNICORN_PORT}",
                    "--chdir",
                    str(RUN / "wsgi"),
                    "--access-logfile",
                    "/dev/null",
                    "--error-logfile",
                    str(RUN / "wsgi" / "error.log"),
                    "app:app",
                ],
                RUN / "wsgi" / "stdout.log",
            )
            if not wait_tcp(GUNICORN_PORT):
                die("Gunicorn did not bind its port")

        apache, apache_log = start(
            [APACHE, "-f", str(apache_cfg), "-DFOREGROUND"], RUN / "apache" / "stdout.log"
        )
        vapache, vapache_log = start(
            [str(VAPACHED), "-f", str(vapache_cfg), "-DFOREGROUND"],
            RUN / "vapache" / "stdout.log",
        )
        if not wait_tcp(AP_PORT) or not wait_tcp(VP_PORT):
            die("front-end server did not bind ports (see /tmp/vapache-app-bench/*/stdout.log)")

        for sc in selected:
            a_status, _, a_marker = probe(AP_PORT, sc["path"], sc["marker"])
            v_status, _, v_marker = probe(VP_PORT, sc["path"], sc["marker"])
            print(f"probe {sc['name']}: apache={a_status} vapache={v_status}")
            if a_status != 200 or v_status != 200 or not a_marker or not v_marker:
                die(f"fixture probe failed for {sc['name']}")

        rows = []
        print(f"\n{'scenario':30} {'apache rps':>12} {'vapache rps':>12} {'ratio':>7} {'a mean':>8} {'v mean':>8}")
        for sc in selected:
            row = dict(name=sc["name"], path=sc["path"], servers={})
            endpoints = (("apache", AP_PORT), ("vapache", VP_PORT))
            for _, port in endpoints:
                measure(port, sc["path"], max(0.5, duration / 2), sc["conc"])
            collected = {server: [] for server, _ in endpoints}
            for sample in range(samples):
                order = endpoints if sample % 2 == 0 else tuple(reversed(endpoints))
                for server, port in order:
                    value = measure(port, sc["path"], duration, sc["conc"])
                    if value["non2xx"] or any(value["socket_errors"]):
                        die(
                            f"invalid {server} sample for {sc['name']}: "
                            f"non2xx={value['non2xx']} socket_errors={value['socket_errors']}"
                        )
                    collected[server].append(value)
            for server, _ in endpoints:
                vals = collected[server]
                vals.sort(key=lambda x: x["rps"] or 0)
                row["servers"][server] = vals[len(vals) // 2]
            a = row["servers"]["apache"]["rps"] or 0
            v = row["servers"]["vapache"]["rps"] or 0
            row["ratio"] = v / a if a else None
            rows.append(row)
            print(
                f"{sc['name']:30} {a:12.0f} {v:12.0f} {row['ratio'] or 0:7.2f}x "
                f"{row['servers']['apache']['mean_ms'] or 0:8.2f} {row['servers']['vapache']['mean_ms'] or 0:8.2f}",
                flush=True,
            )

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sample_seconds": duration,
            "samples": samples,
            "scenarios": rows,
        }
        results = BENCH / "results"
        results.mkdir(exist_ok=True)
        (results / f"app-{stamp}.json").write_text(json.dumps(out, indent=2))
        report = BENCH / "APP_RESULTS.md"
        lines = [
            "# PHP-FPM and Gunicorn application benchmark\n\n",
            f"Generated: {out['timestamp']}\n\n",
            f"Method: {samples} x {duration:g}s samples per server after warm-up; "
            "PHP-FPM over a Unix socket, Gunicorn with 8 sync workers behind the "
            "HTTP proxy; access logs disabled.\n\n",
            "| scenario | apache req/s | vapache req/s | ratio | apache mean ms | vapache mean ms | apache p99 ms | vapache p99 ms |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for row in rows:
            a, v = row["servers"]["apache"], row["servers"]["vapache"]
            lines.append(
                f"| {row['name']} | {a['rps'] or 0:.0f} | {v['rps'] or 0:.0f} | "
                f"{row['ratio'] or 0:.2f}x | {a['mean_ms'] or 0:.2f} | {v['mean_ms'] or 0:.2f} | "
                f"{a['p99_ms'] or 0:.2f} | {v['p99_ms'] or 0:.2f} |"
            )
        lines += [
            "\n## Reading the numbers\n",
            "- Both handlers are deliberately trivial; this isolates the front-end/FastCGI/proxy hop rather than application work.",
            "- PHP-FPM uses a Unix socket and is the production-shaped PHP path. Native `php-cgi` is not used here.",
            "- Vapache's PHP result keeps its stable-path ownership, writeability, ACL, endpoint-inode and peer-credential checks enabled; Apache does not perform an equivalent per-request proof.",
            "- Gunicorn uses eight default sync workers; vapache intentionally does not pool backend connections without strict response-framing checks. A real WSGI request with application latency will spend most of its time in the app, not this hop.",
            "- Run-to-run variance is material on a shared host; the ratios are more useful than absolute req/s.",
        ]
        report.write_text("\n".join(lines) + "\n")
        print(f"\nresults: {results / f'app-{stamp}.json'}\nreport:  {report}")
    finally:
        if not args.keep:
            stop(vapache, vapache_log)
            stop(apache, apache_log)
            stop(gunicorn, gunicorn_log)
            stop(fpm, fpm_log)
        else:
            print(f"kept running; fixture: {RUN}")


if __name__ == "__main__":
    main()
