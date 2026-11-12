#!/usr/bin/env python3
"""Static-only body handling probes."""
import struct
import sys
import time

sys.path.insert(0, "/tmp/opencode/h2lab")
from h2raw import *
import hpack

PORT = int(open("/tmp/opencode/h2lab/port.env").read().strip().split("=")[1])


def enc(hs):
    return hpack.Encoder().encode(hs)


def read(s, t=1.0):
    return read_frames(s, t)


def new_conn():
    s = connect(PORT)
    s.sendall(frame(4, 0, 0, b""))
    return s


def show(tag, fs):
    out = []
    for f in fs:
        if isinstance(f[0], str):
            out.append(f[0])
        elif f[0] == 1:
            hdrs = decode_headers(f[3])
            out.append(f"HEADERS({f[2]}) {[(k, v[:30]) for k, v in hdrs if k == b':status' or k.startswith(b'x-')][:4]}")
        else:
            out.append(f"{FRAME_TYPES.get(f[0], f[0])}(f={f[1]},sid={f[2]},{f[3][:16].hex()})")
    print(tag, out)


# GET with a small body
s = new_conn()
s.sendall(frame(1, 0x4, 1, enc([(":method", "GET"), (":scheme", "https"), (":authority", "localhost"), (":path", "/"), ("content-length", "5")])))
s.sendall(frame(0, 0x1, 1, b"hello"))
show("GET body 5:", read(s, 1.0))
s.close()

# POST with body
s = new_conn()
s.sendall(frame(1, 0x4, 1, enc([(":method", "POST"), (":scheme", "https"), (":authority", "localhost"), (":path", "/"), ("content-length", "5")])))
s.sendall(frame(0, 0x1, 1, b"hello"))
show("POST body 5:", read(s, 1.0))
s.close()

# GET with body, no content-length, DATA EOS
s = new_conn()
s.sendall(frame(1, 0x4, 1, enc([(":method", "GET"), (":scheme", "https"), (":authority", "localhost"), (":path", "/")])))
s.sendall(frame(0, 0x1, 1, b"hello"))
show("GET unknown-length body:", read(s, 1.0))
s.close()

# GET declared 200000 > limit? just check response
s = new_conn()
s.sendall(frame(1, 0x4, 1, enc([(":method", "GET"), (":scheme", "https"), (":authority", "localhost"), (":path", "/"), ("content-length", "200000")])))
s.sendall(frame(0, 0x0, 1, b"x" * 16384))
show("GET declared 200000 partial:", read(s, 1.0))
s.sendall(frame(3, 0, 1, struct.pack(">I", 8)))
s.close()

# GET with body then RST mid-body (drain interrupted)
s = new_conn()
s.sendall(frame(1, 0x4, 1, enc([(":method", "GET"), (":scheme", "https"), (":authority", "localhost"), (":path", "/"), ("content-length", "100")])))
s.sendall(frame(0, 0x0, 1, b"x" * 10))
time.sleep(0.1)
s.sendall(frame(3, 0, 1, struct.pack(">I", 8)))
show("GET body RST mid:", read(s, 0.5))
s.close()
