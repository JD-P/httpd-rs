#!/usr/bin/env python3
"""Container-only process, syscall and resource failure scenarios.

The normal test suite owns deterministic in-process failpoints.  This runner
is deliberately external: it operates on the release daemon under cgroups,
ptrace syscall injection and real child-process termination.  tests/chaos.sh
supplies the container isolation and the minimum capabilities for each mode.
"""

import argparse
import http.client
import os
import resource
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VAPACHED = Path(os.environ.get("VAPACHED", ROOT / "target/release/vapached"))


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def make_tree(base: Path) -> tuple[Path, Path]:
    logs = base / "logs"
    www = base / "www"
    logs.mkdir()
    www.mkdir()
    base.chmod(0o755)
    logs.chmod(0o755)
    www.chmod(0o755)
    return logs, www


def wait_for_port(port: int, process: subprocess.Popen, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"vapached exited with status {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("timed out waiting for vapached")


def stop_process_group(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def process_children(parent_pid: int) -> list[int]:
    """Return direct children without requiring CONFIG_CHECKPOINT_RESTORE."""
    children = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            status = (path / "status").read_text()
        except (FileNotFoundError, PermissionError):
            continue
        for line in status.splitlines():
            if line.startswith("PPid:") and int(line.split()[1]) == parent_pid:
                children.append(int(path.name))
                break
    return sorted(children)


def http_get(port: int, path: str = "/index.html") -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path, headers={"Host": "localhost", "Connection": "close"})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def tls_get(port: int) -> tuple[int, bytes]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(
        "127.0.0.1", port, timeout=5, context=context
    )
    try:
        connection.request(
            "GET", "/index.html", headers={"Host": "localhost", "Connection": "close"}
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def plain_config(base: Path, port: int) -> Path:
    config = base / "httpd.conf"
    config.write_text(
        f'''ServerRoot "{base}"
Listen 127.0.0.1:{port}
PidFile "{base}/logs/vapached.pid"
ErrorLog "{base}/logs/error.log"
User www-data
Group www-data
ServerName localhost
TraceEnable Off
EnableSendfile On
DocumentRoot "{base}/www"
<Directory "{base}/www">
    AllowOverride None
    Require all granted
</Directory>
'''
    )
    config.chmod(0o644)
    return config


def assert_injected(trace: Path, syscall: str) -> None:
    text = trace.read_text(errors="replace") if trace.exists() else ""
    if syscall not in text or "INJECTED" not in text:
        raise AssertionError(f"strace did not inject {syscall}; trace was:\n{text[-4000:]}")


def syscall_failures() -> None:
    """Exercise actual kernel-boundary failures without production hooks."""
    with tempfile.TemporaryDirectory(prefix="vapache-chaos-syscall-") as temporary:
        base = Path(temporary)
        logs, www = make_tree(base)
        body = (b"vapache-sendfile-fallback\n" * 65536)[: 1024 * 1024]
        (www / "index.html").write_bytes(body)
        (www / "index.html").chmod(0o644)
        port = free_port()
        config = plain_config(base, port)
        trace = logs / "sendfile.trace"
        output_path = logs / "process.log"
        with output_path.open("wb") as output:
            process = subprocess.Popen(
                [
                    "strace",
                    "--follow-forks",
                    "--quiet=attach,exit",
                    "--output",
                    str(trace),
                    "--trace=sendfile",
                    "--inject=sendfile:error=EIO:when=1",
                    str(VAPACHED),
                    "-f",
                    str(config),
                    "-DFOREGROUND",
                ],
                cwd=ROOT,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                wait_for_port(port, process)
                status, received = http_get(port)
                assert status == 200, f"sendfile fallback returned HTTP {status}"
                assert received == body, "sendfile fallback returned a partial/corrupt body"
                status, received = http_get(port)
                assert (status, received) == (200, body), "daemon was unhealthy after EIO"
            except Exception:
                output.flush()
                details = output_path.read_text(errors="replace")
                raise AssertionError(f"live sendfile injection failed:\n{details}")
            finally:
                stop_process_group(process)
        assert_injected(trace, "sendfile")

        open_trace = logs / "openat2.trace"
        injected = subprocess.run(
            [
                "strace",
                "--follow-forks",
                "--quiet=attach,exit",
                "--output",
                str(open_trace),
                "--trace=openat2",
                # The first openat2 is the intentionally optional Apache
                # envvars lookup; fail the configuration file open itself.
                "--inject=openat2:error=EIO:when=2",
                str(VAPACHED),
                "-t",
                "-f",
                str(config),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
        )
        assert injected.returncode != 0, (
            "configuration load ignored injected openat2 EIO:\n"
            + injected.stdout.decode(errors="replace")
        )
        assert b"Syntax OK" not in injected.stdout
        assert_injected(open_trace, "openat2")
        control = subprocess.run(
            [str(VAPACHED), "-t", "-f", str(config)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
        )
        assert control.returncode == 0 and b"Syntax OK" in control.stdout, control.stdout.decode(
            errors="replace"
        )
    print("chaos: real sendfile/openat2 failures pass")


def broker_death() -> None:
    """Kill the privileged TLS file broker and require atomic reload failure."""
    if os.geteuid() != 0:
        raise AssertionError("TLS broker death scenario must start as container root")
    with tempfile.TemporaryDirectory(prefix="vapache-chaos-broker-") as temporary:
        base = Path(temporary)
        logs, www = make_tree(base)
        expected = b"healthy after broker death\n"
        (www / "index.html").write_bytes(expected)
        (www / "index.html").chmod(0o644)
        cert = base / "cert.pem"
        key = base / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        cert.chmod(0o644)
        key.chmod(0o600)
        port = free_port()
        config = base / "httpd.conf"
        config.write_text(
            f'''ServerRoot "{base}"
Listen 127.0.0.1:{port}
PidFile "{logs}/vapached.pid"
ErrorLog "{logs}/error.log"
User www-data
Group www-data
ServerName localhost
TraceEnable Off
Protocols http/1.1
DocumentRoot "{www}"
<Directory "{www}">
    AllowOverride None
    Require all granted
</Directory>
<VirtualHost *:{port}>
    ServerName localhost
    SSLEngine On
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCertificateFile "{cert}"
    SSLCertificateKeyFile "{key}"
    DocumentRoot "{www}"
</VirtualHost>
'''
        )
        config.chmod(0o644)
        output_path = logs / "process.log"
        with output_path.open("wb") as output:
            process = subprocess.Popen(
                [str(VAPACHED), "-f", str(config), "-DFOREGROUND"],
                cwd=ROOT,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                wait_for_port(port, process)
                assert tls_get(port) == (200, expected)
                server_pid = int((logs / "vapached.pid").read_text().strip())
                deadline = time.monotonic() + 5
                children: list[int] = []
                while time.monotonic() < deadline:
                    children = process_children(server_pid)
                    if children:
                        break
                    time.sleep(0.05)
                assert len(children) == 1, f"expected one TLS broker child, got {children}"
                os.kill(children[0], signal.SIGKILL)
                os.kill(server_pid, signal.SIGHUP)

                error_log = logs / "error.log"
                deadline = time.monotonic() + 10
                reload_log = ""
                while time.monotonic() < deadline:
                    if not Path(f"/proc/{server_pid}").exists():
                        raise AssertionError(
                            "vapached died after broker termination"
                        )
                    reload_log = (
                        error_log.read_text(errors="replace") if error_log.exists() else ""
                    )
                    if "reload rejected; continuing with previous configuration" in reload_log:
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError(f"reload rejection was not logged:\n{reload_log}")
                assert tls_get(port) == (200, expected), "old TLS generation was not retained"
            except Exception:
                output.flush()
                details = output_path.read_text(errors="replace")
                error_details = (
                    (logs / "error.log").read_text(errors="replace")
                    if (logs / "error.log").exists()
                    else ""
                )
                raise AssertionError(
                    "TLS broker death scenario failed "
                    f"(launcher status={process.poll()}):\n{details}\n{error_details}"
                )
            finally:
                stop_process_group(process)
    print("chaos: TLS broker death preserves the previous configuration")


def resource_limits() -> None:
    """Run the live connection soak only after verifying hard container limits."""
    memory_max = Path("/sys/fs/cgroup/memory.max").read_text().strip()
    pids_max = Path("/sys/fs/cgroup/pids.max").read_text().strip()
    nofile_soft, nofile_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    assert memory_max != "max" and int(memory_max) <= 256 * 1024 * 1024
    assert pids_max != "max" and int(pids_max) <= 128
    assert nofile_soft <= 256 and nofile_hard <= 256
    environment = os.environ.copy()
    environment.update(
        {
            "VAPACHED": str(VAPACHED),
            "SOAK_SECONDS": os.environ.get("CHAOS_SOAK_SECONDS", "15"),
            # The container has one CPU. Four busy clients sustain pressure
            # without turning ephemeral-port exhaustion into the test oracle.
            "SOAK_WORKERS": os.environ.get("CHAOS_SOAK_WORKERS", "4"),
        }
    )
    subprocess.run(
        [sys.executable, str(ROOT / "tests/soak.py")],
        cwd=ROOT,
        env=environment,
        check=True,
        timeout=60,
    )
    print(
        "chaos: constrained soak passes "
        f"(memory={memory_max}, pids={pids_max}, nofile={nofile_soft})"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("resources", "syscalls", "broker"))
    args = parser.parse_args()
    if not VAPACHED.is_file():
        raise SystemExit(f"missing release daemon: {VAPACHED}")
    if args.mode == "resources":
        resource_limits()
    elif args.mode == "syscalls":
        syscall_failures()
    else:
        broker_death()


if __name__ == "__main__":
    main()
