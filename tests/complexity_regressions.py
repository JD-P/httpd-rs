#!/usr/bin/env python3
"""Bound adversarial parser growth and detect accidental superlinear work."""

import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def timed(command, timeout=30):
    started = time.monotonic()
    subprocess.run(command, cwd=ROOT, check=True, timeout=timeout,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return time.monotonic() - started


def main():
    # Release-mode property/fault tests exercise long malformed byte streams,
    # regex expressions and every read split without debug-build noise.
    command = [
        "cargo", "test", "--release", "-p", "httpd-rs",
        "--test", "properties", "--test", "fault_injection",
    ]
    # Compile outside the time budget so a cold CI cache cannot look like an
    # algorithmic regression.
    subprocess.run(command + ["--no-run"], cwd=ROOT, check=True, timeout=300,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elapsed = timed([
        *command,
        "--", "--test-threads=1",
    ], timeout=180)
    if elapsed > 120:
        raise SystemExit(f"complexity-regressions: suite took {elapsed:.1f}s")
    print(f"complexity-regressions: pass ({elapsed:.2f}s)")


if __name__ == "__main__":
    main()
