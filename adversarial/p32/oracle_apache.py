#!/usr/bin/env python3
"""Apache 2.4.69 oracle for P32.

The same 8-source, 32-stream partial-body hold is pointed at Apache httpd
with an equivalent CGI handler that blocks reading stdin.  A ninth source then
requests /small.txt; Apache answers it because its per-connection h2 streams
are not a process-wide 256-stream lease.
"""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import h2bodyhold

APACHE = "/usr/sbin/apache2"
MODULES = "/usr/lib/apache2/modules"
RUN = Path("/tmp/opencode/p32-apache")
TLS_PORT = 19996


def setup_apache() -> Path:
    import shutil

    shutil.rmtree(RUN, ignore_errors=True)
    for d in ("logs", "www", "cgi-bin"):
        (RUN / d).mkdir(parents=True, exist_ok=True)
    RUN.chmod(0o755)
    (RUN / "logs").chmod(0o777)
    (RUN / "www").chmod(0o755)
    (RUN / "cgi-bin").chmod(0o755)
    (RUN / "www" / "small.txt").write_bytes(b"small-p32\n")
    script = RUN / "cgi-bin" / "hold.sh"
    script.write_text("#!/bin/sh\n# Block until the client sends body data or closes stdin.\nread line\nprintf 'Status: 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n'\nsleep 30\n")
    script.chmod(0o755)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "2", "-subj", "/CN=p32.local",
            "-keyout", str(RUN / "key.pem"), "-out", str(RUN / "cert.pem"),
        ],
        check=True, capture_output=True,
    )
    (RUN / "cert.pem").chmod(0o644)
    (RUN / "key.pem").chmod(0o600)
    conf = RUN / "httpd.conf"
    conf.write_text(f'''ServerRoot "{RUN}"
Listen 127.0.0.1:{TLS_PORT}
User www-data
Group www-data
PidFile "{RUN}/logs/httpd.pid"
ErrorLog "{RUN}/logs/error.log"
LogLevel warn
ServerName p32.local
Timeout 60
KeepAliveTimeout 5
ServerLimit 512
MaxRequestWorkers 512
DocumentRoot "{RUN}/www"
<Directory />
    Require all denied
</Directory>
<Directory "{RUN}/www">
    Options FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
ScriptAlias /hold "{RUN}/cgi-bin/hold.sh"
<Directory "{RUN}/cgi-bin">
    Options +ExecCGI
    Require all granted
</Directory>
LoadModule mpm_event_module {MODULES}/mod_mpm_event.so
LoadModule mime_module {MODULES}/mod_mime.so
LoadModule dir_module {MODULES}/mod_dir.so
LoadModule alias_module {MODULES}/mod_alias.so
LoadModule cgi_module {MODULES}/mod_cgi.so
LoadModule authz_core_module {MODULES}/mod_authz_core.so
LoadModule authz_host_module {MODULES}/mod_authz_host.so
LoadModule ssl_module {MODULES}/mod_ssl.so
LoadModule http2_module {MODULES}/mod_http2.so
LoadModule socache_shmcb_module {MODULES}/mod_socache_shmcb.so
SSLSessionCache shmcb:{RUN}/logs/ssl_scache(512000)
TypesConfig /etc/mime.types
Protocols h2 http/1.1
SSLEngine on
SSLCertificateFile "{RUN}/cert.pem"
SSLCertificateKeyFile "{RUN}/key.pem"
''')
    conf.chmod(0o644)
    return conf


def start_apache(conf: Path) -> None:
    subprocess.run([APACHE, "-d", str(RUN), "-f", str(conf), "-k", "start"],
                   check=True, capture_output=True)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", TLS_PORT), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise SystemExit("apache did not start")


def main() -> None:
    conf = setup_apache()
    start_apache(conf)
    h2bodyhold.TLS_PORT = TLS_PORT
    try:
        print("baseline:", h2bodyhold.victim_probe(), flush=True)
        holders = [h2bodyhold.BodyHolder(f"127.0.0.{i + 2}", 32) for i in range(8)]
        for h in holders:
            while h.open_one():
                pass
        time.sleep(1.5)
        for h in holders:
            h.drain()
        print(f"held: sent={sum(h.total_opened for h in holders)} "
              f"active={sum(len(h.active) for h in holders)} "
              f"ended={sum(h.total_ended for h in holders)} "
              f"statuses={[h.statuses for h in holders]}", flush=True)
        for i in range(8):
            print(f"t={i * 5}s victim={h2bodyhold.victim_probe()}", flush=True)
            time.sleep(5)
        for h in holders:
            h.close()
        time.sleep(2)
        print("after release:", h2bodyhold.victim_probe(), flush=True)
    finally:
        subprocess.run([APACHE, "-d", str(RUN), "-f", str(conf), "-k", "stop"],
                       capture_output=True)


if __name__ == "__main__":
    main()
