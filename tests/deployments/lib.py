"""Shared primitives for real-application deployment scenarios.

The application containers are deliberately treated as untrusted.  They may
only see a per-run staging directory under /tmp; the repository, Docker socket
and arbitrary host paths are never mounted into them.
"""

from __future__ import annotations

import base64
import contextlib
import grp
import http.client
import json
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable


ROOT = Path(__file__).resolve().parents[2]
DOCKER_SOCKET = Path("/var/run/docker.sock")


class DeploymentError(RuntimeError):
    """A scenario failed in an actionable way."""


def command(
    args: Iterable[str | os.PathLike[str]],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float | None = None,
    capture: bool = True,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    argv = [os.fspath(arg) for arg in args]
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        timeout=timeout,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        check=False,
    )
    if check and result.returncode != 0:
        output = (result.stdout or "").strip()
        raise DeploymentError(
            f"command failed ({result.returncode}): {' '.join(argv)}"
            + (f"\n{output}" if output else "")
        )
    return result


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for(
    predicate: Callable[[], bool],
    *,
    timeout: float,
    description: str,
    interval: float = 0.1,
) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as error:  # readiness deliberately tolerates startup races
            last_error = error
        time.sleep(interval)
    suffix = f": {last_error}" if last_error else ""
    raise DeploymentError(f"timed out waiting for {description}{suffix}")


def wait_for_path(path: Path, *, timeout: float = 30) -> None:
    wait_for(path.exists, timeout=timeout, description=str(path))


def make_readable_tree(root: Path) -> None:
    """Make staged public/application content readable by the service user."""
    os.chmod(root, 0o755)
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        if path.is_dir():
            os.chmod(path, 0o755)
        elif path.is_file():
            executable = path.stat().st_mode & 0o111
            os.chmod(path, 0o755 if executable else 0o644)


def request(
    port: int,
    path: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 15,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        return response.status, {key.lower(): value for key, value in response.getheaders()}, payload
    finally:
        connection.close()


def require_response(
    port: int,
    path: str,
    *,
    status: int = 200,
    contains: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[dict[str, str], bytes]:
    actual, response_headers, body = request(port, path, headers=headers)
    if actual != status:
        raise DeploymentError(f"{path}: expected HTTP {status}, received {actual}: {body[:500]!r}")
    if contains is not None and contains not in body:
        raise DeploymentError(f"{path}: response did not contain {contains!r}: {body[:500]!r}")
    return response_headers, body


def wait_http(port: int, path: str = "/", *, timeout: float = 30) -> None:
    def ready() -> bool:
        try:
            status, _, _ = request(port, path, timeout=1)
            return 100 <= status < 600
        except (OSError, http.client.HTTPException):
            return False

    wait_for(ready, timeout=timeout, description=f"HTTP service on 127.0.0.1:{port}{path}")


def service_identity() -> tuple[str, str]:
    """Return the identity Vapache should use for a deployment test."""
    if os.geteuid() == 0 or privilege_prefix():
        try:
            pwd.getpwnam("www-data")
            grp.getgrnam("www-data")
            return "www-data", "www-data"
        except KeyError:
            pass
    return pwd.getpwuid(os.geteuid()).pw_name, grp.getgrgid(os.getegid()).gr_name


def privilege_prefix() -> list[str]:
    if os.geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    if not sudo:
        return []
    probe = subprocess.run(
        [sudo, "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
    )
    return [sudo, "-n"] if probe.returncode == 0 else []


@dataclass
class VapacheProcess:
    binary: Path
    config: Path
    log: Path
    pid_file: Path
    process: subprocess.Popen[bytes] | None = None
    _log_handle: object | None = None

    def start(self, *, timeout: float = 30) -> None:
        prefix = privilege_prefix()
        check = [*prefix, os.fspath(self.binary), "-f", os.fspath(self.config), "-t", "--strict-config"]
        command(check, timeout=timeout)
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self._log_handle = self.log.open("ab")
        self.process = subprocess.Popen(
            [*prefix, os.fspath(self.binary), "-f", os.fspath(self.config), "-DFOREGROUND"],
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def reload(self) -> None:
        if not self.pid_file.exists():
            raise DeploymentError(f"Vapache did not write {self.pid_file}")
        pid = int(self.pid_file.read_text().strip())
        prefix = privilege_prefix()
        if prefix:
            command([*prefix, "kill", "-HUP", str(pid)])
        else:
            os.kill(pid, signal.SIGHUP)

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=5)
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None

    def assert_running(self) -> None:
        if self.process is None or self.process.poll() is not None:
            tail = self.log.read_text(errors="replace")[-4000:] if self.log.exists() else ""
            raise DeploymentError(f"Vapache exited unexpectedly\n{tail}")


@dataclass
class ApacheProcess:
    config: Path
    log: Path
    process: subprocess.Popen[bytes] | None = None
    _log_handle: object | None = None

    def start(self) -> None:
        apache = shutil.which("apache2")
        if not apache:
            raise DeploymentError("differential benchmarking requires apache2")
        prefix = privilege_prefix()
        command([*prefix, apache, "-f", os.fspath(self.config), "-t"], timeout=30)
        self._log_handle = self.log.open("ab")
        self.process = subprocess.Popen(
            [*prefix, apache, "-f", os.fspath(self.config), "-DFOREGROUND"],
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=5)
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None


def paths_overlap(first: Path, second: Path) -> bool:
    first = first.resolve()
    second = second.resolve()
    return first == second or first in second.parents or second in first.parents


def validate_bind_source(source: Path, run_dir: Path) -> None:
    resolved = source.resolve()
    if paths_overlap(resolved, ROOT):
        raise DeploymentError(f"container bind mount overlaps the source checkout: {resolved}")
    if resolved == DOCKER_SOCKET or DOCKER_SOCKET in resolved.parents:
        raise DeploymentError(f"container may not mount the Docker socket: {resolved}")
    try:
        resolved.relative_to(run_dir.resolve())
    except ValueError as error:
        raise DeploymentError(
            f"container bind source must be inside the scenario staging directory: {resolved}"
        ) from error


@dataclass
class ComposeProject:
    compose_file: Path
    project: str
    run_dir: Path
    env: dict[str, str]
    images: tuple[str, ...]
    artifact_dir: Path
    remove_images: bool = False

    def _base(self) -> list[str]:
        return ["docker", "compose", "-f", os.fspath(self.compose_file), "-p", self.project]

    def _environment(self) -> dict[str, str]:
        merged = os.environ.copy()
        merged.update(self.env)
        return merged

    def validate(self) -> None:
        rendered = command(
            [*self._base(), "config", "--format", "json"], env=self._environment(), timeout=30
        ).stdout
        try:
            model = json.loads(rendered)
        except json.JSONDecodeError as error:
            raise DeploymentError(f"Docker Compose emitted invalid JSON: {error}") from error
        networks = model.get("networks", {})
        for service_name, service in model.get("services", {}).items():
            if service.get("privileged"):
                raise DeploymentError(f"{service_name}: privileged containers are forbidden")
            if not service.get("read_only"):
                raise DeploymentError(f"{service_name}: container root filesystem must be read-only")
            if "no-new-privileges:true" not in (service.get("security_opt") or []):
                raise DeploymentError(f"{service_name}: no-new-privileges is required")
            if "ALL" not in (service.get("cap_drop") or []):
                raise DeploymentError(f"{service_name}: all ambient capabilities must be dropped")
            if service.get("network_mode"):
                raise DeploymentError(f"{service_name}: explicit/host network mode is forbidden")
            if service.get("build"):
                raise DeploymentError(f"{service_name}: application images must not build from the checkout")
            image = service.get("image")
            if image not in self.images:
                raise DeploymentError(f"{service_name}: undeclared or unpinned image {image!r}")
            for network_name in (service.get("networks") or {}):
                if not networks.get(network_name, {}).get("internal"):
                    raise DeploymentError(f"{service_name}: network {network_name!r} is not internal")
            for port in service.get("ports", []) or []:
                if port.get("host_ip") not in ("127.0.0.1", "::1"):
                    raise DeploymentError(f"{service_name}: published ports must bind only to loopback")
            for volume in service.get("volumes", []) or []:
                if volume.get("type") == "bind":
                    validate_bind_source(Path(volume["source"]), self.run_dir)
            for mount in service.get("volumes", []) or []:
                if str(mount.get("target", "")) == os.fspath(DOCKER_SOCKET):
                    raise DeploymentError(f"{service_name}: Docker socket mount is forbidden")

    def pull(self) -> None:
        self.validate()
        command([*self._base(), "pull"], env=self._environment(), timeout=600, capture=False)

    def up(self) -> None:
        self.validate()
        command(
            [*self._base(), "up", "--detach", "--wait", "--wait-timeout", "120"],
            env=self._environment(),
            timeout=180,
            capture=False,
        )
        self.validate_live_mounts()

    def validate_live_mounts(self) -> None:
        ids = command(
            [
                "docker",
                "ps",
                "--quiet",
                "--filter",
                f"label=com.docker.compose.project={self.project}",
            ],
            timeout=30,
        ).stdout.split()
        if not ids:
            raise DeploymentError(f"Compose project {self.project} has no running containers")
        for container_id in ids:
            inspection = json.loads(command(["docker", "inspect", container_id], timeout=30).stdout)[0]
            host_config = inspection.get("HostConfig", {})
            if host_config.get("Privileged") or not host_config.get("ReadonlyRootfs"):
                raise DeploymentError(f"live container {container_id} violated root-filesystem isolation")
            if "no-new-privileges" not in " ".join(host_config.get("SecurityOpt") or []):
                raise DeploymentError(f"live container {container_id} lacks no-new-privileges")
            if "ALL" not in (host_config.get("CapDrop") or []):
                raise DeploymentError(f"live container {container_id} did not drop all capabilities")
            for mount in inspection.get("Mounts", []):
                if mount.get("Type") == "bind":
                    validate_bind_source(Path(mount["Source"]), self.run_dir)

    def exec(self, service: str, args: list[str], *, user: str | None = None) -> str:
        command_line = [*self._base(), "exec", "--no-TTY"]
        if user:
            command_line.extend(["--user", user])
        command_line.extend([service, *args])
        return command(command_line, env=self._environment(), timeout=120).stdout

    def collect_logs(self) -> None:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        result = command(
            [*self._base(), "logs", "--no-color", "--timestamps"],
            env=self._environment(),
            timeout=60,
            check=False,
        )
        (self.artifact_dir / "containers.log").write_text(result.stdout or "")

    def down(self) -> None:
        with contextlib.suppress(Exception):
            self.collect_logs()
        command(
            [*self._base(), "down", "--volumes", "--remove-orphans", "--timeout", "10"],
            env=self._environment(),
            timeout=120,
            check=False,
        )
        if self.remove_images:
            for image in self.images:
                command(["docker", "image", "rm", image], timeout=120, check=False)


@dataclass
class CaseContext:
    scenario_id: str
    case_id: str
    run_dir: Path
    artifact_dir: Path
    vapached: Path
    images: tuple[str, ...]
    remove_images: bool
    benchmark: bool
    cleanup: list[Callable[[], None]] = field(default_factory=list)

    def add_cleanup(self, callback: Callable[[], None]) -> None:
        self.cleanup.append(callback)

    def close(self) -> None:
        failures: list[str] = []
        for callback in reversed(self.cleanup):
            try:
                callback()
            except Exception as error:  # cleanup must continue to the final resource
                failures.append(str(error))
        if failures:
            raise DeploymentError("cleanup failures: " + "; ".join(failures))

    def compose(self, compose_file: Path, env: dict[str, str]) -> ComposeProject:
        project = "vap_" + "".join(ch if ch.isalnum() else "_" for ch in self.case_id.lower())[-48:]
        project += f"_{os.getpid()}"
        instance = ComposeProject(
            compose_file=compose_file,
            project=project,
            run_dir=self.run_dir,
            env=env,
            images=self.images,
            artifact_dir=self.artifact_dir,
            remove_images=self.remove_images,
        )
        self.add_cleanup(instance.down)
        return instance


def basic_authorization(user: str, password: str) -> str:
    encoded = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {encoded}"


def apache_modules(names: Iterable[str]) -> str:
    module_dir = Path("/usr/lib/apache2/modules")
    special = {"mpm_event": "mpm_event_module"}
    lines: list[str] = []
    for name in names:
        module = module_dir / f"mod_{name}.so"
        if not module.exists():
            raise DeploymentError(f"Apache reference module is missing: {module}")
        symbol = special.get(name, f"{name}_module")
        lines.append(f"LoadModule {symbol} {module}")
    return "\n".join(lines)


def common_apache_config(
    run_dir: Path,
    port: int,
    document_root: Path,
    *,
    modules: Iterable[str],
    extra: str = "",
) -> str:
    server_root = run_dir / f"apache-{port}"
    logs = server_root / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    os.chmod(logs, 0o777)
    user, group = service_identity()
    return f"""ServerRoot "{server_root}"
{apache_modules(modules)}
Listen {port}
User {user}
Group {group}
PidFile "{logs / 'apache.pid'}"
ErrorLog "{logs / 'error.log'}"
LogLevel warn
ServerName deployment.test
Timeout 30
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 3
DocumentRoot "{document_root}"
<Directory />
    AllowOverride None
    Require all denied
</Directory>
<Directory "{document_root}">
    Options FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
{extra.rstrip()}
"""


def start_apache(context: CaseContext, config_text: str, port: int) -> ApacheProcess:
    config = context.run_dir / f"apache-{port}.conf"
    config.write_text(config_text)
    shutil.copy2(config, context.artifact_dir / "apache.conf")
    process = ApacheProcess(config=config, log=context.artifact_dir / "apache.log")
    context.add_cleanup(process.stop)
    process.start()
    wait_http(port)
    return process


def differential_benchmark(
    vapache_port: int,
    apache_port: int,
    path: str,
    artifact: Path,
    *,
    headers: tuple[str, ...] = (),
) -> None:
    wrk = shutil.which("wrk")
    if not wrk:
        raise DeploymentError("differential benchmarking requires wrk")

    def wrk_command(port: int, duration: str, connections: int) -> list[str]:
        argv = [wrk, "-t2", f"-c{connections}", f"-d{duration}", "--latency"]
        for header in headers:
            argv.extend(["-H", header])
        argv.append(f"http://127.0.0.1:{port}{path}")
        return argv

    for port in (vapache_port, apache_port):
        command(wrk_command(port, "2s", 4), timeout=20)

    samples: dict[str, list[dict[str, object]]] = {"vapache": [], "apache": []}
    order = (("vapache", vapache_port), ("apache", apache_port), ("apache", apache_port), ("vapache", vapache_port), ("vapache", vapache_port), ("apache", apache_port))
    for server, port in order:
        output = command(wrk_command(port, "5s", 8), timeout=30).stdout
        match = re.search(r"Requests/sec:\s+([0-9.]+)", output)
        if match is None:
            raise DeploymentError(f"wrk did not report throughput for {server}: {output}")
        non_success = re.search(r"Non-2xx or 3xx responses:\s+(\d+)", output)
        socket_errors = re.search(
            r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", output
        )
        if non_success and int(non_success.group(1)):
            raise DeploymentError(f"wrk observed non-success responses from {server}: {output}")
        if socket_errors and any(int(value) for value in socket_errors.groups()):
            raise DeploymentError(f"wrk observed socket errors from {server}: {output}")
        latency = re.search(r"Latency\s+([0-9.]+)(us|ms|s)\s+", output)
        p99 = re.search(r"^\s*99%\s+([0-9.]+)(us|ms|s)\s*$", output, re.MULTILINE)

        def milliseconds(match: re.Match[str] | None) -> float | None:
            if match is None:
                return None
            value = float(match.group(1))
            return value / 1000 if match.group(2) == "us" else value * 1000 if match.group(2) == "s" else value

        samples[server].append(
            {
                "requests_per_second": float(match.group(1)),
                "mean_latency_ms": milliseconds(latency),
                "p99_latency_ms": milliseconds(p99),
                "raw": output,
            }
        )
    summary = {
        "path": path,
        "samples": samples,
        "median_requests_per_second": {
            name: sorted(float(sample["requests_per_second"]) for sample in values)[len(values) // 2]
            for name, values in samples.items()
        },
    }
    vapache_rps = summary["median_requests_per_second"]["vapache"]
    apache_rps = summary["median_requests_per_second"]["apache"]
    summary["vapache_to_apache_ratio"] = vapache_rps / apache_rps if apache_rps else None
    artifact.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


def common_vapache_config(
    run_dir: Path,
    port: int,
    document_root: Path,
    *,
    capabilities: Iterable[str] = (),
    extra: str = "",
) -> tuple[str, Path]:
    server_root = run_dir / "vapache"
    logs = server_root / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    os.chmod(logs, 0o777)
    document_root.mkdir(parents=True, exist_ok=True)
    user, group = service_identity()
    pid_file = logs / "vapached.pid"
    capability_lines = "".join(f"VapacheCapability {name} On\n" for name in capabilities)
    config = f"""ServerRoot "{server_root}"
Listen {port}
User {user}
Group {group}
PidFile "{pid_file}"
ErrorLog "{logs / 'error.log'}"
LogLevel warn
ServerName deployment.test
Timeout 30
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 3
DocumentRoot "{document_root}"
TypesConfig /etc/mime.types
{capability_lines}<Directory />
    AllowOverride None
    Require all denied
</Directory>
<Directory "{document_root}">
    Options FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
{extra.rstrip()}
"""
    return config, pid_file


def start_vapache(context: CaseContext, config_text: str, pid_file: Path, port: int) -> VapacheProcess:
    config = context.run_dir / "vapache.conf"
    config.write_text(config_text)
    shutil.copy2(config, context.artifact_dir / "vapache.conf")
    process = VapacheProcess(
        binary=context.vapached,
        config=config,
        log=context.artifact_dir / "vapached.log",
        pid_file=pid_file,
    )
    context.add_cleanup(process.stop)
    process.start()
    wait_http(port)
    process.assert_running()
    return process

