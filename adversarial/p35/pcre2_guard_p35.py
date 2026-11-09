#!/usr/bin/env python3
"""Pass-35-B: PCRE2 auto-possessification differential on an ACL guard.

Vapache compiles PCRE2 patterns with a non-backtracking automata engine and
translates `\\S*`, `.*` and `\\N*` into ordinary repetitions. PCRE2 (Apache)
auto-possessifies those repetitions when the next atom is `\\R`, `\\v` or
`\\h`, so for certain subjects Apache finds no match while Vapache does.

A negated guard (`!~`) that denies values which do *not* match the pattern is
therefore fail-open on Vapache for a header value containing the NEL byte
0x85. The harness starts Apache and vapached on loopback ports, sends the
same request, and retains the differential.

Usage:
    python3 adversarial/p35/pcre2_guard_p35.py
    python3 adversarial/p35/pcre2_guard_p35.py --keep
"""

from __future__ import annotations

import http.client
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VAPACHED = REPO / "target" / "release" / "vapached"
APACHE = os.environ.get("P35_APACHE", "/usr/sbin/apache2")
APACHE_MODULES = Path(os.environ.get("P35_APACHE_MODULES", "/usr/lib/apache2/modules"))
HARNESS = Path("/tmp/opencode/p35-pcre2-harness")

PATTERNS = [
    ("S-star-v", r"\S*\v"),
    ("S-star-R", r"\S*\R"),
    ("N-plus-R", r"\N+\R"),
    ("S-plus-R", r"\S+\R"),
    ("plain-v-control", r"\v"),
]


def free_port(start: int) -> int:
    for candidate in range(start, start + 200):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            try:
                listener.bind(("127.0.0.1", candidate))
            except OSError:
                continue
            return candidate
    raise SystemExit("no free port")


def request(port: int, value: str):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    try:
        connection.putrequest("GET", "/index.html")
        connection.putheader("X-Test", value)
        connection.endheaders()
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def stop(process) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        process.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def main() -> int:
    keep = "--keep" in sys.argv
    if not VAPACHED.exists():
        raise SystemExit(f"missing binary: {VAPACHED} (cargo build --release -p vapached)")
    if HARNESS.exists():
        shutil.rmtree(HARNESS)
    HARNESS.mkdir(parents=True)
    failures = 0
    rows = []
    for name, pattern in PATTERNS:
        case = HARNESS / name
        www = case / "www"
        www.mkdir(parents=True)
        (www / "index.html").write_text("public\n")
        os.chmod(www, 0o755)
        (case / "apache" / "logs").mkdir(parents=True)
        (case / "vapache" / "logs").mkdir(parents=True)
        port_a = free_port(37000)
        port_v = free_port(37700)
        guard = f'<If "%{{HTTP:X-Test}} !~ /{pattern}/">\n    Require all denied\n</If>\n'
        apache_conf = case / "apache.conf"
        apache_conf.write_text(
            f"""ServerRoot "{case / 'apache'}"
LoadModule mpm_event_module {APACHE_MODULES / 'mod_mpm_event.so'}
LoadModule mime_module {APACHE_MODULES / 'mod_mime.so'}
LoadModule dir_module {APACHE_MODULES / 'mod_dir.so'}
LoadModule authz_core_module {APACHE_MODULES / 'mod_authz_core.so'}
LoadModule authz_host_module {APACHE_MODULES / 'mod_authz_host.so'}
TypesConfig /etc/mime.types
Listen {port_a}
User www-data
Group www-data
PidFile "{case / 'apache' / 'logs' / 'apache.pid'}"
ErrorLog "{case / 'apache' / 'logs' / 'error.log'}"
ServerName p35b.test
DocumentRoot "{www}"
<Directory />
  Require all denied
</Directory>
<Directory "{www}">
  Require all granted
  {guard}</Directory>
""")
        vapache_conf = case / "vapache.conf"
        vapache_conf.write_text(
            f"""ServerRoot "{case / 'vapache'}"
Listen {port_v}
User www-data
Group www-data
PidFile "{case / 'vapache' / 'logs' / 'vapached.pid'}"
ErrorLog "{case / 'vapache' / 'logs' / 'error.log'}"
ServerName p35b.test
DocumentRoot "{www}"
TypesConfig /etc/mime.types
<Directory />
  Require all denied
</Directory>
<Directory "{www}">
  Require all granted
  {guard}</Directory>
""")
        built = subprocess.run(
            [str(VAPACHED), "-f", str(vapache_conf), "-t"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if built.returncode != 0:
            print(f"## {name}: vapache rejected the guard: {built.stdout.strip()[-160:]}")
            failures += 1
            continue
        a_log = (case / "apache.log").open("ab")
        v_log = (case / "vapached.log").open("ab")
        apache = subprocess.Popen(
            [APACHE, "-f", str(apache_conf), "-DFOREGROUND"],
            stdout=a_log, stderr=subprocess.STDOUT, start_new_session=True)
        vapache = subprocess.Popen(
            [str(VAPACHED), "-f", str(vapache_conf), "-DFOREGROUND"],
            stdout=v_log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    request(port_a, "ok")
                    request(port_v, "ok")
                    break
                except OSError:
                    time.sleep(0.1)
            print(f"## {name}  pattern={pattern}")
            for label, value in (("plain", "plainvalue"), ("nel", "A\u0085B")):
                a_status, _ = request(port_a, value)
                v_status, _ = request(port_v, value)
                print(f"   {label:5} apache={a_status} vapache={v_status}")
                rows.append((name, label, a_status, v_status))
                if label == "plain" and (a_status, v_status) != (403, 403):
                    print("   -> UNEXPECTED plain control")
                    failures += 1
                if name != "plain-v-control" and label == "nel":
                    if a_status != 403 or v_status != 200:
                        print("   -> UNEXPECTED NEL divergence")
                        failures += 1
                if name == "plain-v-control" and label == "nel":
                    if (a_status, v_status) != (200, 200):
                        print("   -> UNEXPECTED simple-pattern control")
                        failures += 1
        finally:
            stop(apache)
            stop(vapache)
            a_log.close()
            v_log.close()
    if keep:
        print(f"fixtures retained under {HARNESS}")
    else:
        shutil.rmtree(HARNESS, ignore_errors=True)
    if failures:
        print(f"P35-B REGRESSION: {failures} unexpected verdict(s)")
        return 1
    print("P35-B LIVE: PCRE2 auto-possessification over-matches on vapache")
    return 0


if __name__ == "__main__":
    sys.exit(main())