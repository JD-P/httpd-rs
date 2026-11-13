"""Minimal raw HTTP/2 client over TLS with ALPN for httpd-rs h2 testing."""
import socket
import ssl
import struct
import time
import hpack

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_TYPES = {
    0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS",
    5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE",
    9: "CONTINUATION", 10: "ALTSVC", 11: "ORIGIN", 12: "PRIORITY_UPDATE",
}


def connect(port, host="127.0.0.1", timeout=5.0, alpn=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if alpn:
        ctx.set_alpn_protocols(["h2"])
    raw = socket.create_connection((host, port), timeout=timeout)
    sock = ctx.wrap_socket(raw, server_hostname="localhost")
    if alpn:
        assert sock.selected_alpn_protocol() == "h2", sock.selected_alpn_protocol()
    sock.settimeout(timeout)
    sock.sendall(PREFACE)
    return sock


def frame(ftype, flags, stream_id, payload=b""):
    return (
        len(payload).to_bytes(3, "big")
        + bytes([ftype & 0xFF, flags & 0xFF])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def parse_frames(buf):
    out = []
    while len(buf) >= 9:
        length = int.from_bytes(buf[0:3], "big")
        ftype, flags = buf[3], buf[4]
        sid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
        if len(buf) < 9 + length:
            break
        payload = buf[9:9 + length]
        buf = buf[9 + length:]
        out.append((ftype, flags, sid, payload))
    return out, buf


def read_frames(sock, duration=1.0, max_bytes=1 << 20):
    """Read frames until quiet for `duration` or max_bytes."""
    frames = []
    buf = b""
    deadline = time.time() + duration
    while time.time() < deadline:
        sock.settimeout(max(0.05, deadline - time.time()))
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        except (ConnectionResetError, ssl.SSLError, OSError):
            frames.append(("EOF", 0, 0, b""))
            break
        if not chunk:
            frames.append(("EOF", 0, 0, b""))
            break
        buf += chunk
        new, buf = parse_frames(buf)
        frames.extend(new)
    return frames


def settings_payload(*pairs):
    return b"".join(struct.pack(">HI", k, v) for k, v in pairs)


def goaway(last, code, debug=b""):
    return struct.pack(">II", last, code) + debug


def decode_headers(block):
    dec = hpack.Decoder()
    try:
        return dec.decode(block, raw=True)
    except Exception as e:
        return [("decode-error", str(e))]
