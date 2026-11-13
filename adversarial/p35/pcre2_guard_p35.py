#!/usr/bin/env python3
"""Pass-35-B regression: PCRE2 auto-possessification in ACL guards.

httpd-rs compiles PCRE2 patterns with a non-backtracking automata engine and
translates `\\S*` and `\\N*` into ordinary repetitions. PCRE2 (Apache)
auto-possessifies those repetitions when the next atom is `\\R`, `\\v` or
`\\h`, so for certain subjects Apache finds no match while httpd-rs does.

A negated guard (`!~`) used to fail open on httpd-rs for a header value
containing the NEL byte 0x85. The compatibility layer cannot exactly model
these PCRE2 optimizer semantics, so httpd-rs now rejects the unsafe four
patterns at configuration load. The harness verifies that Apache accepts
them, httpd-rs fails closed, and the simple `\v` control still agrees live.

Usage:
    python3 adversarial/p35/pcre2_guard_p35.py
    python3 adversarial/p35/pcre2_guard_p35.py --keep
"""

from __future__ import annotations

import http.client
import grp
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HTTPD_RS = REPO / "target" / "release" / "httpd-rs"
APACHE = os.environ.get("P35_APACHE", "/usr/sbin/apache2")
APACHE_MODULES = Path(os.environ.get("P35_APACHE_MODULES", "/usr/lib/apache2/modules"))
HARNESS = Path("/tmp/opencode/p35-pcre2-harness")

if os.geteuid() == 0:
    SERVICE_USER = "www-data"
    SERVICE_GROUP = "www-data"
else:
    SERVICE_USER = pwd.getpwuid(os.geteuid()).pw_name
    SERVICE_GROUP = grp.getgrgid(os.getegid()).gr_name

PATTERNS = [
    ("S-star-v", r"\S*\v"),
    ("S-star-R", r"\S*\R"),
    ("N-plus-R", r"\N+\R"),
    ("S-plus-R", r"\S+\R"),
    ("plain-v-control", r"\v"),
]
FAIL_CLOSED = {"S-star-v", "S-star-R", "N-plus-R", "S-plus-R"}


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
    if not HTTPD_RS.exists():
        raise SystemExit(f"missing binary: {HTTPD_RS} (cargo build --release -p httpd-rs)")
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
        (case / "httpd-rs" / "logs").mkdir(parents=True)
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
User {SERVICE_USER}
Group {SERVICE_GROUP}
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
        httpd_rs_conf = case / "httpd-rs.conf"
        httpd_rs_conf.write_text(
            f"""ServerRoot "{case / 'httpd-rs'}"
Listen {port_v}
User {SERVICE_USER}
Group {SERVICE_GROUP}
PidFile "{case / 'httpd-rs' / 'logs' / 'httpd-rs.pid'}"
ErrorLog "{case / 'httpd-rs' / 'logs' / 'error.log'}"
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
            [str(HTTPD_RS), "-f", str(httpd_rs_conf), "-t"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        apache_test = subprocess.run(
            [APACHE, "-t", "-f", str(apache_conf)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if apache_test.returncode != 0:
            print(f"## {name}: Apache rejected the guard: {apache_test.stdout.strip()[-160:]}")
            failures += 1
            continue
        if name in FAIL_CLOSED:
            if built.returncode == 0:
                print(f"## {name}: httpd-rs accepted an unrepresentable guard")
                failures += 1
            else:
                print(f"## {name}  pattern={pattern}")
                print("   apache=accepted httpd-rs=rejected (fail closed)")
            continue
        if built.returncode != 0:
            print(f"## {name}: httpd-rs rejected the guard: {built.stdout.strip()[-160:]}")
            failures += 1
            continue
        a_log = (case / "apache.log").open("ab")
        v_log = (case / "httpd-rs.log").open("ab")
        apache = subprocess.Popen(
            [APACHE, "-f", str(apache_conf), "-DFOREGROUND"],
            stdout=a_log, stderr=subprocess.STDOUT, start_new_session=True)
        httpd_rs = subprocess.Popen(
            [str(HTTPD_RS), "-f", str(httpd_rs_conf), "-DFOREGROUND"],
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
                print(f"   {label:5} apache={a_status} httpd-rs={v_status}")
                rows.append((name, label, a_status, v_status))
                if label == "plain" and (a_status, v_status) != (403, 403):
                    print("   -> UNEXPECTED plain control")
                    failures += 1
                if name == "plain-v-control" and label == "nel":
                    if (a_status, v_status) != (200, 200):
                        print("   -> UNEXPECTED simple-pattern control")
                        failures += 1
        finally:
            stop(apache)
            stop(httpd_rs)
            a_log.close()
            v_log.close()
    if keep:
        print(f"fixtures retained under {HARNESS}")
    else:
        shutil.rmtree(HARNESS, ignore_errors=True)
    if failures:
        print(f"P35-B REGRESSION: {failures} unexpected verdict(s)")
        return 1
    print("P35-B REMEDIATED: unrepresentable guards fail closed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
