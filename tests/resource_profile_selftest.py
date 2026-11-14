#!/usr/bin/env python3
"""Exercise the portable procfs collector without requiring perf or a server."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import resource_profile
import resource_budget_sweep


def main() -> int:
    sample = resource_profile.sample_process(os.getpid())
    assert sample is not None
    assert sample["stat"]["resident_bytes"] > 0
    assert sample["stat"]["threads"] >= 1

    with tempfile.TemporaryDirectory(prefix="httpd-rs-resource-profile-") as directory:
        output = Path(directory) / "profile.json"
        profiler = resource_profile.Profiler(
            output=output,
            label="selftest",
            match="python",
            interval=0.001,
            perf="none",
            max_samples=32,
            perf_processes=1,
            attached_pid=os.getpid(),
        )
        profiler.sample()
        allocation = bytearray(2 * 1024 * 1024)
        with open("/dev/null", "wb") as sink:
            sink.write(b"resource-profile-selftest")
            accumulator = 0
            for value in range(250_000):
                accumulator ^= value
            profiler.sample()
        assert allocation[0] == 0
        assert accumulator >= 0
        document = profiler.finish(None, None)
        persisted = json.loads(output.read_text())
        assert document["matched_processes"] == 1
        assert persisted["peaks"]["resident_bytes"] > 0
        assert persisted["peaks"]["threads"] >= 1
        assert persisted["peaks"]["fds"] >= 3
        assert persisted["observed_resources"]["resident-memory"]
        assert persisted["observed_resources"]["tasks"]
        assert persisted["observed_resources"]["file-descriptors"]
        assert persisted["observed_resources"]["wall-time"]
        assert persisted["observed_resources"]["disk-capacity"]
        assert persisted["observed_resources"]["filesystem-inodes"]
        assert persisted["filesystems"]
        assert persisted["network_namespaces"]
        policy = json.loads((Path(__file__).parents[1] / "docs/resource-warrant-policy.json").read_text())
        assert set(persisted["observed_resources"]) == {
            resource["id"] for resource in policy["resources"]
        }
        if resource_profile.cgroup_v2_path(os.getpid()) is not None:
            assert persisted["collector"]["cgroup_v2"]
            assert persisted["cgroups"]
    markdown = resource_budget_sweep.render_markdown(
        {
            "git_revision": "selftest",
            "points": [
                {
                    "axis": "bytes",
                    "value": 1,
                    "requests": 1,
                    "concurrency": 1,
                    "cpu_ticks_delta": 0,
                    "statuses": {"200": 1},
                    "process_after": {"resident_bytes": 1024 * 1024},
                    "rejection_delta": {},
                }
            ],
        }
    )
    assert "| bytes | 1 |" in markdown
    assert "reporting-only" in markdown
    print("resource-profile: procfs collector self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
