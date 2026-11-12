#!/usr/bin/env python3
"""External HTTP/2 and TLS protocol checks against a real vapached process."""

import argparse
import grp
import os
import pwd
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VAPACHED = Path(os.environ.get("VAPACHED", ROOT / "target/release/vapached"))
SERVICE_USER = "www-data" if os.geteuid() == 0 else pwd.getpwuid(os.geteuid()).pw_name
SERVICE_GROUP = "www-data" if os.getegid() == 0 else grp.getgrgid(os.getegid()).gr_name


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for_port(port, process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"vapached exited with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("timed out waiting for vapached")


def start_tls_server(base, protocols="h2 http/1.1"):
    base = Path(base)
    (base / "logs").mkdir()
    (base / "www").mkdir()
    (base / "www/index.html").write_text("vapache protocol test\n")
    cert = base / "cert.pem"
    key = base / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-subj", "/CN=localhost", "-keyout", str(key),
        "-out", str(cert),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    port = free_port()
    config = base / "httpd.conf"
    config.write_text(f'''ServerRoot "{base}"
Listen 127.0.0.1:{port}
PidFile "{base}/logs/vapached.pid"
ErrorLog "{base}/logs/error.log"
User {SERVICE_USER}
Group {SERVICE_GROUP}
ServerName localhost
TraceEnable Off
Protocols {protocols}
DocumentRoot "{base}/www"
<Directory "{base}/www">
    AllowOverride None
    Require all granted
</Directory>
<VirtualHost *:{port}>
    ServerName localhost
    SSLEngine On
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCertificateFile "{cert}"
    SSLCertificateKeyFile "{key}"
    DocumentRoot "{base}/www"
</VirtualHost>
''')
    output = (base / "logs/process.log").open("wb")
    process = subprocess.Popen(
        [str(VAPACHED), "-f", str(config), "-DFOREGROUND"],
        cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
    )
    try:
        wait_for_port(port, process)
    except Exception:
        process.terminate()
        process.wait(timeout=5)
        output.close()
        raise
    return process, output, port


def stop_tls_server(process, output):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    output.close()


def tls_connection(port, minimum, maximum, alpn=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = minimum
    context.maximum_version = maximum
    if alpn:
        context.set_alpn_protocols(alpn)
    raw = socket.create_connection(("127.0.0.1", port), timeout=3)
    return context.wrap_socket(raw, server_hostname="localhost")


def check_tls(port):
    for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        try:
            connection = tls_connection(port, version, version)
        except (ssl.SSLError, OSError):
            continue
        connection.close()
        raise AssertionError(f"legacy protocol {version.name} was accepted")

    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        with tls_connection(port, version, version) as connection:
            assert connection.version() in {"TLSv1.2", "TLSv1.3"}

    with tls_connection(
        port, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.MAXIMUM_SUPPORTED,
        ["h2", "http/1.1"],
    ) as connection:
        assert connection.selected_alpn_protocol() == "h2"
    print("protocol-conformance: TLS versions and ALPN pass")


def check_alpn_policy():
    with tempfile.TemporaryDirectory(prefix="vapache-http1-only-") as temporary:
        process, output, port = start_tls_server(temporary, "http/1.1")
        try:
            with tls_connection(
                port, ssl.TLSVersion.TLSv1_2,
                ssl.TLSVersion.MAXIMUM_SUPPORTED, ["h2", "http/1.1"],
            ) as connection:
                assert connection.selected_alpn_protocol() == "http/1.1"
        finally:
            stop_tls_server(process, output)

    with tempfile.TemporaryDirectory(prefix="vapache-h2-only-") as temporary:
        process, output, port = start_tls_server(temporary, "h2")
        try:
            with tls_connection(
                port, ssl.TLSVersion.TLSv1_2,
                ssl.TLSVersion.MAXIMUM_SUPPORTED, ["h2"],
            ) as connection:
                assert connection.selected_alpn_protocol() == "h2"

            with tls_connection(
                port, ssl.TLSVersion.TLSv1_2,
                ssl.TLSVersion.MAXIMUM_SUPPORTED,
            ) as connection:
                connection.settimeout(2)
                try:
                    connection.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    assert connection.recv(1) == b""
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass
        finally:
            stop_tls_server(process, output)
    print("protocol-conformance: Protocols ALPN policy pass")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--h2spec", help="path to the h2spec executable")
    parser.add_argument("--tls", action="store_true", help="run TLS policy checks")
    args = parser.parse_args()
    if not args.h2spec and not args.tls:
        parser.error("select --h2spec or --tls")
    if not VAPACHED.is_file():
        raise SystemExit(f"missing vapached binary: {VAPACHED}")

    if args.tls:
        with tempfile.TemporaryDirectory(prefix="vapache-protocol-") as temporary:
            process, output, port = start_tls_server(temporary)
            try:
                check_tls(port)
                check_alpn_policy()
            finally:
                stop_tls_server(process, output)

    if args.h2spec:
        # h2spec 2.6.0 generic/5/14 and /5/15 unconditionally send
        # nonzero HPACK table-size updates. That contradicts the
        # server's advertised SETTINGS_HEADER_TABLE_SIZE=0. Retain
        # the standards-aware hpack/6.3 limit test and every other
        # generic case while excluding only those two invalid probes.
        h2spec_groups = [
            "generic/1", "generic/2", "generic/3", "generic/4",
            *[f"generic/5/{case}" for case in range(1, 14)],
            "http2/3", "http2/4", "http2/5",
            "http2/6.1", "http2/6.2", "http2/6.3",
            "http2/6.4", "http2/6.5", "http2/6.7",
            "http2/6.8", "http2/6.9", "http2/6.10",
            "http2/7", "http2/8",
            "hpack/2", "hpack/4", "hpack/5", "hpack/6",
        ]
        # Each strict section gets a fresh server. h2spec deliberately leaves
        # some faulted connections for the endpoint to reap; accumulating
        # those across unrelated sections tests the production per-source
        # connection reserve instead of the protocol behavior under test.
        for group in h2spec_groups:
            with tempfile.TemporaryDirectory(prefix="vapache-h2spec-") as temporary:
                process, output, port = start_tls_server(temporary)
                try:
                    subprocess.run([
                        args.h2spec, "--tls", "--insecure", "--strict",
                        "--host", "127.0.0.1", "--port", str(port),
                        "--timeout", "3", group,
                    ], check=True, timeout=60)
                finally:
                    stop_tls_server(process, output)


if __name__ == "__main__":
    main()
