#!/usr/bin/env python3
"""Profile resources consumed by httpd-rs during an arbitrary local workload.

This is the dynamic half of the request-resource warrant.  It deliberately
uses Linux's stable procfs/cgroup interfaces as the always-available collector
and treats perf as an optional call-stack/counter engine.  The wrapper follows
the selected server plus every descendant it creates, so CGI/helper processes
remain attributed to the request path without charging unrelated benchmark
clients or application backends.

Examples:
  python3 tests/resource_profile.py run --output artifacts/resource/bench.json -- \
      python3 bench/bench.py --quick
  python3 tests/resource_profile.py run --perf record --output artifacts/resource/apps.json -- \
      python3 tests/deployments/harness.py --profile canonical --benchmark
  python3 tests/resource_profile.py attach --pid 1234 --seconds 30 --output /tmp/httpd-rs.json
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
PAGE_BYTES = os.sysconf("SC_PAGE_SIZE")
TICKS_PER_SECOND = os.sysconf("SC_CLK_TCK")
STATUS_BYTES = {
    "VmPeak",
    "VmSize",
    "VmHWM",
    "VmRSS",
    "RssAnon",
    "RssFile",
    "RssShmem",
    "VmData",
    "VmStk",
    "VmExe",
    "VmLib",
    "VmSwap",
}
SMAPS_BYTES = {
    "Rss",
    "Pss",
    "Pss_Anon",
    "Pss_File",
    "Pss_Shmem",
    "Shared_Clean",
    "Shared_Dirty",
    "Private_Clean",
    "Private_Dirty",
    "Anonymous",
    "Swap",
}
IO_FIELDS = {"rchar", "wchar", "syscr", "syscw", "read_bytes", "write_bytes"}
CGROUP_GAUGES = {"memory.current", "memory.peak", "pids.current", "pids.peak"}
CGROUP_COUNTER_PREFIXES = ("cpu.", "io.")


def git_revision() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def parse_key_values(path: Path, wanted: set[str], *, kib: bool = False) -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return values
    for line in lines:
        if ":" not in line:
            continue
        name, raw = line.split(":", 1)
        if name not in wanted:
            continue
        fields = raw.split()
        if not fields:
            continue
        try:
            value = int(fields[0])
        except ValueError:
            continue
        if kib and len(fields) > 1 and fields[1].lower() == "kb":
            value *= 1024
        values[name] = value
    return values


def read_integer(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def cgroup_v2_path(pid: int) -> tuple[str, Path] | None:
    """Return the process's unified cgroup without assuming a systemd layout."""
    try:
        lines = (Path("/proc") / str(pid) / "cgroup").read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        hierarchy, controllers, relative = fields
        if hierarchy == "0" and not controllers:
            root = Path("/sys/fs/cgroup") / relative.lstrip("/")
            if root.is_dir():
                return relative, root
    return None


def sample_cgroup(pid: int) -> dict[str, Any] | None:
    located = cgroup_v2_path(pid)
    if located is None:
        return None
    relative, root = located
    values: dict[str, int] = {}
    for name in CGROUP_GAUGES:
        value = read_integer(root / name)
        if value is not None:
            values[name] = value

    for filename, prefix in (("cpu.stat", "cpu"),):
        try:
            lines = (root / filename).read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) != 2:
                continue
            try:
                values[f"{prefix}.{fields[0]}"] = int(fields[1])
            except ValueError:
                pass

    io_totals: dict[str, int] = {}
    try:
        io_lines = (root / "io.stat").read_text().splitlines()
    except OSError:
        io_lines = []
    for line in io_lines:
        for field in line.split()[1:]:
            name, separator, raw = field.partition("=")
            if not separator:
                continue
            try:
                io_totals[name] = io_totals.get(name, 0) + int(raw)
            except ValueError:
                pass
    values.update({f"io.{name}": value for name, value in io_totals.items()})

    limits: dict[str, str] = {}
    for name in ("memory.max", "memory.high", "pids.max", "cpu.max", "io.max"):
        try:
            limits[name] = (root / name).read_text().strip()
        except OSError:
            pass
    return {"path": relative, "values": values, "limits": limits}


def proc_identity(pid: int) -> tuple[int, str, str] | None:
    root = Path("/proc") / str(pid)
    try:
        stat = (root / "stat").read_text()
        close = stat.rfind(")")
        fields = stat[close + 2 :].split()
        ppid = int(fields[1])
        argv = (root / "cmdline").read_bytes().split(b"\0")
        command = " ".join(item.decode(errors="replace") for item in argv if item)
        executable = os.readlink(root / "exe")
        return ppid, command, executable
    except (OSError, ValueError, IndexError):
        return None


def process_table() -> dict[int, tuple[int, str, str]]:
    table: dict[int, tuple[int, str, str]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        identity = proc_identity(pid)
        if identity is not None:
            table[pid] = identity
    return table


def descendants(table: dict[int, tuple[int, str, str]], roots: set[int]) -> set[int]:
    selected = set(roots)
    changed = True
    while changed:
        changed = False
        for pid, (ppid, _, _) in table.items():
            if ppid in selected and pid not in selected:
                selected.add(pid)
                changed = True
    return selected


def executable_matches(command: str, executable: str, needle: str) -> bool:
    argv0 = command.split(" ", 1)[0] if command else ""
    names = {Path(argv0).name, Path(executable).name}
    return any(needle in name for name in names)


def fd_classes(pid: int) -> dict[str, int]:
    counts = {"total": 0, "socket": 0, "pipe": 0, "anon_inode": 0, "file": 0, "other": 0}
    directory = Path("/proc") / str(pid) / "fd"
    try:
        entries = list(directory.iterdir())
    except OSError:
        return counts
    counts["total"] = len(entries)
    for entry in entries:
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        if target.startswith("socket:"):
            kind = "socket"
        elif target.startswith("pipe:"):
            kind = "pipe"
        elif target.startswith("anon_inode:"):
            kind = "anon_inode"
        elif target.startswith("/"):
            kind = "file"
        else:
            kind = "other"
        counts[kind] += 1
    return counts


def sample_process(pid: int) -> dict[str, Any] | None:
    root = Path("/proc") / str(pid)
    try:
        raw_stat = (root / "stat").read_text()
        close = raw_stat.rfind(")")
        fields = raw_stat[close + 2 :].split()
        stat = {
            "ppid": int(fields[1]),
            "minor_faults": int(fields[7]),
            "major_faults": int(fields[9]),
            "user_ticks": int(fields[11]),
            "system_ticks": int(fields[12]),
            "threads": int(fields[17]),
            "start_ticks": int(fields[19]),
            "virtual_bytes": int(fields[20]),
            "resident_bytes": int(fields[21]) * PAGE_BYTES,
        }
        command = (root / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
        executable = os.readlink(root / "exe")
    except (OSError, ValueError, IndexError):
        return None
    status = parse_key_values(root / "status", STATUS_BYTES, kib=True)
    status.update(
        parse_key_values(
            root / "status", {"voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"}
        )
    )
    smaps = parse_key_values(root / "smaps_rollup", SMAPS_BYTES, kib=True)
    io = parse_key_values(root / "io", IO_FIELDS)
    return {
        "pid": pid,
        "command": command,
        "executable": executable,
        "stat": stat,
        "status": status,
        "smaps": smaps,
        "io": io,
        "fds": fd_classes(pid),
    }


def sum_nested(samples: list[dict[str, Any]], section: str, key: str) -> int:
    return sum(int(sample.get(section, {}).get(key, 0)) for sample in samples)


def aggregate_sample(samples: list[dict[str, Any]], elapsed: float) -> dict[str, Any]:
    return {
        "elapsed_seconds": round(elapsed, 6),
        "processes": len(samples),
        "cpu_ticks": sum_nested(samples, "stat", "user_ticks")
        + sum_nested(samples, "stat", "system_ticks"),
        "resident_bytes": sum_nested(samples, "stat", "resident_bytes"),
        "pss_bytes": sum_nested(samples, "smaps", "Pss"),
        "anonymous_bytes": sum_nested(samples, "smaps", "Anonymous"),
        "private_bytes": sum_nested(samples, "smaps", "Private_Clean")
        + sum_nested(samples, "smaps", "Private_Dirty"),
        "swap_bytes": sum_nested(samples, "smaps", "Swap"),
        "threads": sum_nested(samples, "stat", "threads"),
        "fds": sum_nested(samples, "fds", "total"),
        "socket_fds": sum_nested(samples, "fds", "socket"),
        "pipe_fds": sum_nested(samples, "fds", "pipe"),
        "file_fds": sum_nested(samples, "fds", "file"),
        "read_bytes": sum_nested(samples, "io", "read_bytes"),
        "write_bytes": sum_nested(samples, "io", "write_bytes"),
        "read_characters": sum_nested(samples, "io", "rchar"),
        "write_characters": sum_nested(samples, "io", "wchar"),
        "read_syscalls": sum_nested(samples, "io", "syscr"),
        "write_syscalls": sum_nested(samples, "io", "syscw"),
        "minor_faults": sum_nested(samples, "stat", "minor_faults"),
        "major_faults": sum_nested(samples, "stat", "major_faults"),
        "voluntary_context_switches": sum_nested(samples, "status", "voluntary_ctxt_switches"),
        "nonvoluntary_context_switches": sum_nested(
            samples, "status", "nonvoluntary_ctxt_switches"
        ),
    }


@dataclasses.dataclass
class ProcessLifetime:
    pid: int
    command: str
    executable: str
    first_elapsed: float
    last_elapsed: float
    first: dict[str, Any]
    last: dict[str, Any]
    peaks: dict[str, int]

    def update(self, sample: dict[str, Any], elapsed: float) -> None:
        self.last_elapsed = elapsed
        self.last = sample
        for name, value in aggregate_sample([sample], elapsed).items():
            if isinstance(value, int):
                self.peaks[name] = max(self.peaks.get(name, 0), value)

    def document(self) -> dict[str, Any]:
        def delta(section: str, key: str) -> int:
            return max(
                0,
                int(self.last.get(section, {}).get(key, 0))
                - int(self.first.get(section, {}).get(key, 0)),
            )

        return {
            "pid": self.pid,
            "command": self.command,
            "executable": self.executable,
            "first_elapsed_seconds": round(self.first_elapsed, 6),
            "last_elapsed_seconds": round(self.last_elapsed, 6),
            "cpu_seconds": round(
                (delta("stat", "user_ticks") + delta("stat", "system_ticks"))
                / TICKS_PER_SECOND,
                6,
            ),
            "read_bytes": delta("io", "read_bytes"),
            "write_bytes": delta("io", "write_bytes"),
            "read_syscalls": delta("io", "syscr"),
            "write_syscalls": delta("io", "syscw"),
            "minor_faults": delta("stat", "minor_faults"),
            "major_faults": delta("stat", "major_faults"),
            "peaks": self.peaks,
        }


class PerfSession:
    def __init__(self, mode: str, pid: int, output: Path):
        self.mode = mode
        self.pid = pid
        self.output = output
        self.process: subprocess.Popen[bytes] | None = None
        self.error: str | None = None

    def start(self) -> None:
        perf = shutil.which("perf")
        if not perf:
            self.error = "perf is not installed"
            return
        if self.mode == "stat":
            command = [
                perf,
                "stat",
                "-x,",
                "-e",
                "task-clock,cycles,instructions,context-switches,page-faults",
                "-p",
                str(self.pid),
                "-o",
                os.fspath(self.output),
            ]
        else:
            command = [
                perf,
                "record",
                "-F",
                "199",
                "-g",
                "--call-graph",
                "dwarf",
                "-p",
                str(self.pid),
                "-o",
                os.fspath(self.output),
            ]
        try:
            self.process = subprocess.Popen(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True
            )
        except OSError as error:
            self.error = str(error)

    def stop(self) -> dict[str, Any]:
        if self.process is not None and self.process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(os.getpgid(self.process.pid), signal.SIGINT)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.process is not None and self.process.returncode not in (0, -signal.SIGINT):
            error = (self.process.stderr.read() if self.process.stderr else b"").decode(errors="replace")
            self.error = error.strip() or f"perf exited {self.process.returncode}"
        return {
            "mode": self.mode,
            "pid": self.pid,
            "output": os.fspath(self.output),
            "available": self.output.exists() and self.output.stat().st_size > 0,
            "error": self.error,
        }


class Profiler:
    def __init__(
        self,
        *,
        output: Path,
        label: str,
        match: str,
        interval: float,
        perf: str,
        max_samples: int,
        perf_processes: int,
        launched_pid: int | None = None,
        attached_pid: int | None = None,
    ):
        self.output = output
        self.label = label
        self.match = match
        self.interval = interval
        self.perf_mode = perf
        self.max_samples = max_samples
        self.perf_processes = perf_processes
        self.launched_pid = launched_pid
        self.attached_pid = attached_pid
        self.started = time.monotonic()
        self.direct_roots: set[int] = set()
        self.ever_tracked: set[int] = set()
        self.lifetimes: dict[tuple[int, int], ProcessLifetime] = {}
        self.timeline: list[dict[str, Any]] = []
        self.perf_sessions: dict[int, PerfSession] = {}
        self.cgroups: dict[str, dict[str, Any]] = {}

    def select(self, table: dict[int, tuple[int, str, str]]) -> set[int]:
        if self.attached_pid is not None:
            self.direct_roots.add(self.attached_pid)
        if self.launched_pid is not None:
            tree = descendants(table, {self.launched_pid})
            for pid in tree:
                _, command, executable = table.get(pid, (0, "", ""))
                if executable_matches(command, executable, self.match):
                    self.direct_roots.add(pid)
        live_roots = self.direct_roots & table.keys()
        selected = descendants(table, live_roots)
        self.ever_tracked.update(selected)
        return selected

    def start_perf(self, pid: int) -> None:
        if self.perf_mode == "none" or pid in self.perf_sessions:
            return
        if len(self.perf_sessions) >= self.perf_processes:
            return
        suffix = "perf.csv" if self.perf_mode == "stat" else "perf.data"
        path = self.output.with_name(f"{self.output.stem}.{pid}.{suffix}")
        session = PerfSession(self.perf_mode, pid, path)
        self.perf_sessions[pid] = session
        session.start()

    def update_cgroup(self, sample: dict[str, Any], elapsed: float) -> None:
        path = str(sample["path"])
        values = dict(sample["values"])
        state = self.cgroups.get(path)
        if state is None:
            self.cgroups[path] = {
                "path": path,
                "first_elapsed_seconds": elapsed,
                "last_elapsed_seconds": elapsed,
                "first": values,
                "last": values,
                "peaks": values,
                "limits": dict(sample["limits"]),
            }
            return
        state["last_elapsed_seconds"] = elapsed
        state["last"] = values
        state["limits"] = dict(sample["limits"])
        for name, value in values.items():
            state["peaks"][name] = max(int(state["peaks"].get(name, 0)), int(value))

    def cgroup_documents(self) -> list[dict[str, Any]]:
        documents = []
        for state in self.cgroups.values():
            deltas = {}
            for name, value in state["last"].items():
                if name.startswith(CGROUP_COUNTER_PREFIXES):
                    deltas[name] = max(0, int(value) - int(state["first"].get(name, 0)))
            documents.append(
                {
                    "path": state["path"],
                    "first_elapsed_seconds": round(state["first_elapsed_seconds"], 6),
                    "last_elapsed_seconds": round(state["last_elapsed_seconds"], 6),
                    "first": state["first"],
                    "last": state["last"],
                    "peaks": state["peaks"],
                    "counter_deltas": deltas,
                    "limits": state["limits"],
                    "scope_note": (
                        "cgroup values are an independent containment/backstop view and may "
                        "include peer processes outside the matched httpd-rs tree"
                    ),
                }
            )
        return sorted(documents, key=lambda item: item["path"])

    def sample(self) -> None:
        elapsed = time.monotonic() - self.started
        table = process_table()
        selected = self.select(table)
        for pid in sorted(self.direct_roots & selected):
            self.start_perf(pid)
        sampled_cgroups: set[str] = set()
        for pid in sorted(selected):
            cgroup = sample_cgroup(pid)
            if cgroup is not None and cgroup["path"] not in sampled_cgroups:
                sampled_cgroups.add(cgroup["path"])
                self.update_cgroup(cgroup, elapsed)
        samples = [sample for pid in sorted(selected) if (sample := sample_process(pid))]
        for sample in samples:
            key = (sample["pid"], int(sample["stat"]["start_ticks"]))
            lifetime = self.lifetimes.get(key)
            if lifetime is None:
                initial = aggregate_sample([sample], elapsed)
                lifetime = ProcessLifetime(
                    pid=sample["pid"],
                    command=sample["command"],
                    executable=sample["executable"],
                    first_elapsed=elapsed,
                    last_elapsed=elapsed,
                    first=sample,
                    last=sample,
                    peaks={name: value for name, value in initial.items() if isinstance(value, int)},
                )
                self.lifetimes[key] = lifetime
            else:
                lifetime.update(sample, elapsed)
        if samples and len(self.timeline) < self.max_samples:
            self.timeline.append(aggregate_sample(samples, elapsed))

    def finish(self, command: list[str] | None, returncode: int | None) -> dict[str, Any]:
        self.sample()
        perf = [session.stop() for session in self.perf_sessions.values()]
        lifetime_docs = [item.document() for item in self.lifetimes.values()]
        peak_fields = (
            "processes",
            "resident_bytes",
            "pss_bytes",
            "anonymous_bytes",
            "private_bytes",
            "swap_bytes",
            "threads",
            "fds",
            "socket_fds",
            "pipe_fds",
            "file_fds",
        )
        peaks = {
            field: max((int(sample.get(field, 0)) for sample in self.timeline), default=0)
            for field in peak_fields
        }
        cpu_seconds = sum(float(item["cpu_seconds"]) for item in lifetime_docs)
        io_totals = {
            name: sum(int(item[name]) for item in lifetime_docs)
            for name in ("read_bytes", "write_bytes", "read_syscalls", "write_syscalls")
        }
        observed = {
            "cpu-time": cpu_seconds > 0,
            "resident-memory": peaks["resident_bytes"] > 0,
            "private-memory": peaks["private_bytes"] > 0,
            "tasks": peaks["threads"] > 0 or peaks["processes"] > 0,
            "file-descriptors": peaks["fds"] > 0,
            "sockets": peaks["socket_fds"] > 0,
            "pipes": peaks["pipe_fds"] > 0,
            "filesystem-io": io_totals["read_bytes"] > 0 or io_totals["write_bytes"] > 0,
        }
        document = {
            "schema": 1,
            "kind": "httpd-rs-resource-profile",
            "label": self.label,
            "git_revision": git_revision(),
            "created_unix_seconds": time.time(),
            "duration_seconds": round(time.monotonic() - self.started, 6),
            "host": {
                "platform": platform.platform(),
                "kernel": platform.release(),
                "page_bytes": PAGE_BYTES,
                "ticks_per_second": TICKS_PER_SECOND,
            },
            "collector": {
                "interval_seconds": self.interval,
                "process_match": self.match,
                "timeline_truncated": len(self.timeline) >= self.max_samples,
                "procfs": True,
                "cgroup_v2": bool(self.cgroups),
                "perf": self.perf_mode,
            },
            "command": command,
            "returncode": returncode,
            "matched_processes": len(lifetime_docs),
            "peaks": peaks,
            "cpu_seconds": round(cpu_seconds, 6),
            "io_totals": io_totals,
            "observed_resources": observed,
            "processes": sorted(lifetime_docs, key=lambda item: (item["first_elapsed_seconds"], item["pid"])),
            "cgroups": self.cgroup_documents(),
            "timeline": self.timeline,
            "perf_sessions": perf,
        }
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        return document


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label", default="resource-profile")
    parser.add_argument("--match", default="httpd-rs", help="substring of the target executable name")
    parser.add_argument("--interval", type=positive_float, default=0.05)
    parser.add_argument("--max-samples", type=positive_int, default=20_000)
    parser.add_argument("--perf", choices=("none", "stat", "record"), default="none")
    parser.add_argument("--perf-processes", type=positive_int, default=16)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    run = commands.add_parser("run", help="run a workload and discover its httpd-rs descendants")
    add_common(run)
    run.add_argument("command", nargs=argparse.REMAINDER)
    attach = commands.add_parser("attach", help="sample an existing httpd-rs process")
    add_common(attach)
    attach.add_argument("--pid", type=positive_int, required=True)
    attach.add_argument("--seconds", type=positive_float, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.action == "run":
        command = list(args.command)
        if command and command[0] == "--":
            command.pop(0)
        if not command:
            raise SystemExit("resource-profile: run requires a command after --")
        process = subprocess.Popen(command, start_new_session=True)
        profiler = Profiler(
            output=args.output,
            label=args.label,
            match=args.match,
            interval=args.interval,
            perf=args.perf,
            max_samples=args.max_samples,
            perf_processes=args.perf_processes,
            launched_pid=process.pid,
        )
        try:
            while process.poll() is None:
                profiler.sample()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(os.getpgid(process.pid), signal.SIGINT)
            process.wait()
        document = profiler.finish(command, process.returncode)
        if document["matched_processes"] == 0:
            print(
                f"resource-profile: no executable matching {args.match!r} was observed",
                file=sys.stderr,
            )
            return 3 if process.returncode == 0 else int(process.returncode)
        print(
            f"resource-profile: {document['matched_processes']} process(es), "
            f"{document['cpu_seconds']:.3f}s CPU, "
            f"{document['peaks']['resident_bytes']} peak RSS bytes -> {args.output}"
        )
        return int(process.returncode)

    deadline = time.monotonic() + args.seconds
    profiler = Profiler(
        output=args.output,
        label=args.label,
        match=args.match,
        interval=args.interval,
        perf=args.perf,
        max_samples=args.max_samples,
        perf_processes=args.perf_processes,
        attached_pid=args.pid,
    )
    while time.monotonic() < deadline and Path(f"/proc/{args.pid}").exists():
        profiler.sample()
        time.sleep(args.interval)
    document = profiler.finish(None, None)
    print(f"resource-profile: wrote {args.output} ({document['matched_processes']} process(es))")
    return 0 if document["matched_processes"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
