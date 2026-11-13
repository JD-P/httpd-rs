#!/usr/bin/env python3
"""F70 candidate: AccessFileName identity split on a symlinked mapping root."""
from __future__ import annotations
import http.client, os, shutil, socket, subprocess, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "f70-scratch"
HTTPD_RS = Path("/root/httpd-rs/target/release/httpd-rs")
APACHE = "/usr/sbin/apache2"
MODDIR = "/usr/lib/apache2/modules"
PORT = 41210

MODS = "".join(
    f"LoadModule {n}_module {MODDIR}/mod_{n}.so\n"
    for n in ["mpm_event", "mime", "dir", "alias", "cgi", "autoindex",
              "authz_core", "authz_host", "access_compat", "headers",
              "setenvif", "rewrite"]
)

HTADMIN = "Options -ExecCGI\nRequire all denied\n"

CONF = """ServerRoot "{root}"
Listen {port}
User www-data
Group www-data
PidFile {root}/logs/httpd.pid
ErrorLog {root}/logs/error.log
LogLevel warn
ServerName localhost
TypesConfig /etc/mime.types
Options +ExecCGI +FollowSymLinks
AddHandler cgi-script .cgi
DocumentRoot "{root}/tree/www/html"
<Directory "{root}/tree/www/html">
    Require all granted
    AllowOverride All
    AccessFileName .htadmin
</Directory>
"""
CONF_NOAFN = CONF.replace("    AccessFileName .htadmin\n", "")
CONF_PLAIN = (
    CONF_NOAFN
    .replace('DocumentRoot "{root}/tree/www/html"', 'DocumentRoot "{root}/srv/app/public"')
    .replace('<Directory "{root}/tree/www/html">', '<Directory "{root}/srv/app/public">')
)

CGI = (
    "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
    "printf 'F70-EXEC uid='; id -u; uname -n\n"
)


def build(base: Path, symlink: bool) -> None:
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    real = base / "srv/app/public/uploads"
    real.mkdir(parents=True)
    (real / "run.cgi").write_text(CGI)
    os.chmod(real / "run.cgi", 0o755)
    html = base / "tree/www/html"
    if symlink:
        html.parent.mkdir(parents=True)
        os.symlink("../../srv/app/public", html)
    else:
        html.mkdir(parents=True)
        ls = html / "uploads"
        ls.mkdir()
        (ls / "run.cgi").write_text(CGI)
        os.chmod(ls / "run.cgi", 0o755)
    (base / "logs").mkdir(exist_ok=True)
    (base / "logs").chmod(0o777)


def write_conf(path: Path, text: str, port: int, root: Path) -> None:
    path.write_text(text.replace("{root}", str(root)).replace("{port}", str(port)))


def start(cmd, log: Path):
    f = open(log, "ab")
    p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
    return p, f


def wait_port(port, deadline=10):
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def fetch(port, path, timeout=10):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def run(name: str, conf: str, symlink: bool, with_htadmin: bool, url: str = "/uploads/run.cgi"):
    global PORT
    PORT += 2
    ap_port, vp_port = PORT, PORT + 1
    base = ROOT / name
    build(base, symlink)
    if with_htadmin:
        (base / "srv/app/public/uploads/.htadmin").write_text(HTADMIN)
        (base / "srv/app/public/uploads/.htadmin").chmod(0o755)
    vpath = base / "vp.conf"
    apath = base / "apache.conf"
    write_conf(vpath, conf, vp_port, base)
    write_conf(apath, MODS + "\n" + conf, ap_port, base)
    subprocess.run(["pkill", "-9", "-f", f"{ROOT}/{name}"], capture_output=True)
    ap, apf = start([APACHE, "-f", str(apath), "-k", "start"], base / "logs/apache.out")
    vp, vpf = start([str(HTTPD_RS), "-f", str(vpath), "-DFOREGROUND"], base / "logs/httpd-rs.out")
    ok_ap, ok_vp = wait_port(ap_port), wait_port(vp_port)
    s_ap, b_ap = fetch(ap_port, url) if ok_ap else (-1, b"start failed - see logs")
    s_vp, b_vp = fetch(vp_port, url) if ok_vp else (-1, b"start failed - see logs")
    print(f"=== {name}")
    print(f"    apache  : {s_ap} {b_ap.decode('utf8', 'replace').strip().splitlines()[:1]}")
    print(f"    httpd-rs: {s_vp} {b_vp.decode('utf8', 'replace').strip().splitlines()[:1]}")
    subprocess.run(["pkill", "-9", "-f", f"{ROOT}/{name}"], capture_output=True)
    if apf: apf.close()
    if vpf: vpf.close()
    return s_ap, s_vp


if __name__ == "__main__":
    run("A-symlink-accessfilename", CONF, symlink=True, with_htadmin=True)
    run("B-noaccessfilename", CONF_NOAFN, symlink=True, with_htadmin=False)
    run("C-plain", CONF_PLAIN, symlink=False, with_htadmin=True)
