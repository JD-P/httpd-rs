#!/usr/bin/env python3
"""P32 rolling hold: refill each timed-out stream immediately on its own
connection, so the process-wide pool stays at its 256-slot ceiling while the
body deadline recycles streams one at a time.  Measures victim refusal rate.
"""
import argparse
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import h2bodyhold


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", type=int, default=8)
    ap.add_argument("--per-source", type=int, default=32)
    ap.add_argument("--path", default="/hold")
    ap.add_argument("--fill-seconds", type=int, default=8)
    ap.add_argument("--measure-seconds", type=int, default=90)
    ap.add_argument("--probe-interval", type=float, default=0.2)
    ap.add_argument("--timeout", type=int, default=60,
                    help="value for the fixture's Timeout directive")
    args = ap.parse_args()

    h2bodyhold.setup()
    if args.timeout != 60:
        conf = h2bodyhold.RUN / "httpd.conf"
        conf.write_text(conf.read_text().replace("Timeout 60", f"Timeout {args.timeout}"))
    proc = h2bodyhold.start()
    try:
        print("baseline:", h2bodyhold.victim_probe(), flush=True)
        holders = [h2bodyhold.BodyHolder(f"127.0.0.{i + 2}", args.per_source, args.path)
                   for i in range(args.sources)]

        def refill(h: h2bodyhold.BodyHolder) -> None:
            try:
                for _ in range(h.limit):
                    if not h.open_one():
                        break
            except (OSError, h2bodyhold.h2.exceptions.ProtocolError):
                pass

        # Fill one connection at a time so the route-probe burst does not trip
        # transient per-source working-set limits.
        for h in holders:
            refill(h)
            time.sleep(0.15)
        time.sleep(1.0)
        for h in holders:
            h.drain()
        print(f"pool filled: active={sum(len(h.active) for h in holders)} "
              f"opened={sum(h.total_opened for h in holders)} "
              f"victim={h2bodyhold.victim_probe()}", flush=True)

        ok = refused = other = 0
        last_refusal = None
        max_gap = 0.0
        start = time.time()
        end = start + args.measure_seconds
        next_probe = start
        while time.time() < end:
            for h in holders:
                before = len(h.active)
                h.drain()
                if len(h.active) < h.limit:
                    refill(h)
            now = time.time()
            if now >= next_probe:
                probe = h2bodyhold.victim_probe()
                if probe.startswith("status=b'200'"):
                    ok += 1
                    if last_refusal is not None:
                        max_gap = max(max_gap, now - last_refusal)
                elif "reset=7" in probe:
                    refused += 1
                    last_refusal = now
                else:
                    other += 1
                next_probe += args.probe_interval
            time.sleep(0.005)
        total = ok + refused + other
        active = sum(len(h.active) for h in holders)
        print(f"rolling: probes={total} refused={refused} served={ok} other={other} "
              f"refusal_ratio={refused / max(total, 1):.3f} "
              f"max_served_gap={max_gap:.2f}s active={active} "
              f"opened={sum(h.total_opened for h in holders)} "
              f"408s={sum(h.total_408 for h in holders)} "
              f"resets={sum(h.total_reset for h in holders)}", flush=True)
        for h in holders:
            h.close()
        time.sleep(1)
        print("after release:", h2bodyhold.victim_probe(), flush=True)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    main()
