#!/usr/bin/env python3
"""Gate gross throughput/error regressions against Apache on the same host."""

import argparse
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("result", nargs="?", help="bench result JSON (default: newest)")
    parser.add_argument(
        "--minimum-ratio",
        type=float,
        default=float(os.environ.get("MIN_HTTPD_RS_APACHE_RATIO", "0.85")),
        help="minimum httpd-rs/Apache requests-per-second ratio per scenario",
    )
    args = parser.parse_args()
    if args.result:
        result = Path(args.result)
    else:
        candidates = sorted((ROOT / "bench/results").glob("[0-9]*.json"))
        if not candidates:
            raise SystemExit("performance-regression: no benchmark result found")
        result = candidates[-1]

    document = json.loads(result.read_text())
    failures = []
    for scenario in document.get("scenarios", []):
        name = scenario.get("name", "unnamed")
        ratio = scenario.get("ratio")
        if ratio is None or ratio < args.minimum_ratio:
            failures.append(f"{name}: throughput ratio {ratio!r}")
        for server, metrics in scenario.get("servers", {}).items():
            failed = metrics.get("failed") or 0
            non2xx = metrics.get("non2xx") or 0
            raw_socket_errors = metrics.get("socket_errors") or {}
            socket_errors = sum(
                raw_socket_errors.values()
                if isinstance(raw_socket_errors, dict)
                else raw_socket_errors
            )
            if server == "httpd-rs" and (failed or non2xx or socket_errors):
                failures.append(
                    f"{name}/{server}: failed={failed}, non2xx={non2xx}, "
                    f"socket-errors={socket_errors}"
                )
    if not document.get("scenarios"):
        failures.append("result contains no scenarios")
    if failures:
        raise SystemExit("performance-regression: " + "; ".join(failures))
    print(
        f"performance-regression: pass ({len(document['scenarios'])} scenarios, "
        f"minimum ratio {args.minimum_ratio:.2f}x)"
    )


if __name__ == "__main__":
    main()
