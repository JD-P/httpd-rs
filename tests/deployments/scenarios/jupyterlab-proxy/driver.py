"""Run JupyterLab through a subpath and execute code over a kernel WebSocket."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import socket
import struct
import time
import uuid
from pathlib import Path

from lib import (
    CaseContext,
    DeploymentError,
    common_apache_config,
    common_vapache_config,
    differential_benchmark,
    free_port,
    request,
    require_response,
    start_apache,
    start_vapache,
    wait_http,
)


HERE = Path(__file__).resolve().parent
TOKEN = "vapache-jupyter-integration-token"


def read_exact(stream: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    while count:
        chunk = stream.recv(count)
        if not chunk:
            raise DeploymentError("Jupyter WebSocket closed during a frame")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def send_frame(stream: socket.socket, opcode: int, payload: bytes) -> None:
    mask = b"jp42"
    length = len(payload)
    if length < 126:
        header = bytes([0x80 | opcode, 0x80 | length])
    elif length <= 0xFFFF:
        header = bytes([0x80 | opcode, 0xFE]) + struct.pack("!H", length)
    else:
        header = bytes([0x80 | opcode, 0xFF]) + struct.pack("!Q", length)
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    stream.sendall(header + mask + masked)


def read_frame(stream: socket.socket) -> tuple[int, bytes]:
    first, second = read_exact(stream, 2)
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exact(stream, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(stream, 8))[0]
    mask = read_exact(stream, 4) if second & 0x80 else b""
    payload = read_exact(stream, length)
    if mask:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return opcode, payload


def open_websocket(port: int, path: str) -> socket.socket:
    stream = socket.create_connection(("127.0.0.1", port), timeout=30)
    stream.settimeout(30)
    # RFC 6455 requires the decoded nonce to be exactly 16 bytes.  Vapache
    # deliberately refuses to enter tunnel mode for malformed upgrade keys.
    key = base64.b64encode(b"vapache-jupyter!").decode()
    head = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Origin: http://127.0.0.1:{port}\r\n\r\n"
    ).encode()
    stream.sendall(head)
    response = bytearray()
    while b"\r\n\r\n" not in response and len(response) <= 65536:
        response.extend(read_exact(stream, 1))
    status_line = bytes(response).split(b"\r\n", 1)[0]
    if b" 101 " not in status_line:
        stream.close()
        raise DeploymentError(f"Jupyter WebSocket upgrade failed: {bytes(response[:2000])!r}")
    headers: dict[bytes, bytes] = {}
    for line in bytes(response).split(b"\r\n")[1:]:
        if b":" in line:
            name, value = line.split(b":", 1)
            headers[name.strip().lower()] = value.strip()
    expected = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    )
    if headers.get(b"sec-websocket-accept") != expected:
        stream.close()
        raise DeploymentError(f"Jupyter WebSocket accept mismatch: {headers}")
    return stream


def create_kernel(port: int, prefix: str) -> str:
    status, _, body = request(
        port,
        f"{prefix}/api/kernels",
        method="POST",
        headers={"Authorization": f"token {TOKEN}", "Content-Type": "application/json"},
        body=b"{}",
        timeout=60,
    )
    if status != 201:
        raise DeploymentError(f"Jupyter kernel creation failed: {status} {body[:2000]!r}")
    try:
        return str(json.loads(body)["id"])
    except (ValueError, KeyError) as error:
        raise DeploymentError(f"Jupyter kernel response was malformed: {body[:2000]!r}") from error


def execute_marker(stream: socket.socket) -> None:
    session = uuid.uuid4().hex
    message = {
        "header": {
            "msg_id": uuid.uuid4().hex,
            "username": "vapache",
            "session": session,
            "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "msg_type": "execute_request",
            "version": "5.3",
        },
        "parent_header": {},
        "metadata": {},
        "content": {
            "code": "print('vapache-jupyter-kernel-marker')",
            "silent": False,
            "store_history": False,
            "user_expressions": {},
            "allow_stdin": False,
            "stop_on_error": True,
        },
        "channel": "shell",
        "buffers": [],
    }
    send_frame(stream, 0x1, json.dumps(message, separators=(",", ":")).encode())
    for _ in range(100):
        opcode, payload = read_frame(stream)
        if opcode == 0x9:
            send_frame(stream, 0xA, payload)
            continue
        if opcode == 0x8:
            raise DeploymentError(f"Jupyter closed the kernel WebSocket: {payload!r}")
        if b"vapache-jupyter-kernel-marker" in payload:
            return
    raise DeploymentError("Jupyter kernel did not return the executed marker")


def run(context: CaseContext, variant: dict[str, str]) -> None:
    frontend_port = free_port()
    prefix = "/jupyter" if variant["mount"] == "subpath" else ""
    base_url = f"{prefix}/" if prefix else "/"
    compose = context.compose(
        HERE / "compose.yml",
        {
            "JUPYTER_BASE_URL": base_url,
            "JUPYTER_TOKEN": TOKEN,
        },
    )
    compose.pull()
    compose.up()
    backend_host = compose.service_ip("jupyter")
    wait_http(
        8888,
        f"{prefix}/api/status?token={TOKEN}",
        timeout=180,
        host=backend_host,
        statuses=(200,),
    )

    empty_docroot = context.run_dir / "empty"
    empty_docroot.mkdir()
    route = base_url
    backend_route = f"http://{backend_host}:8888{base_url}"
    extra = f"""
ProxyPass {route} {backend_route}
ProxyPassReverse {route} {backend_route}
"""
    config, pid_file = common_vapache_config(
        context.run_dir, frontend_port, empty_docroot, extra=extra
    )
    server = start_vapache(context, config, pid_file, frontend_port)
    auth = {"Authorization": f"token {TOKEN}"}
    require_response(frontend_port, f"{prefix}/api/status", contains=b"connections", headers=auth)
    require_response(frontend_port, f"{prefix}/lab?token={TOKEN}", contains=b"JupyterLab")

    kernel = create_kernel(frontend_port, prefix)
    websocket = open_websocket(
        frontend_port,
        f"{prefix}/api/kernels/{kernel}/channels?session_id=vapache-integration&token={TOKEN}",
    )
    try:
        if variant["websocket"] == "execute":
            execute_marker(websocket)
        if variant["reload"] == "while-open":
            server.reload()
            time.sleep(0.5)
            server.assert_running()
            # Vapache deliberately retires tunnels bound to the old policy
            # generation.  Reconnect under the new grant and prove that the
            # kernel survived the reload without keeping stale authority.
            websocket.close()
            websocket = open_websocket(
                frontend_port,
                f"{prefix}/api/kernels/{kernel}/channels?session_id=vapache-integration-reloaded&token={TOKEN}",
            )
            if variant["websocket"] == "execute":
                execute_marker(websocket)
        send_frame(websocket, 0x8, b"\x03\xe8")
    finally:
        websocket.close()

    status, _, body = request(
        frontend_port,
        f"{prefix}/api/kernels/{kernel}",
        method="DELETE",
        headers=auth,
    )
    if status != 204:
        raise DeploymentError(f"Jupyter kernel cleanup failed: {status} {body[:1000]!r}")

    if context.benchmark:
        apache_port = free_port()
        apache_extra = f"""
ProxyPass {route} {backend_route}
ProxyPassReverse {route} {backend_route}
"""
        apache_config = common_apache_config(
            context.run_dir,
            apache_port,
            empty_docroot,
            modules=("mpm_event", "authz_core", "authz_host", "proxy", "proxy_http"),
            extra=apache_extra,
        )
        start_apache(context, apache_config, apache_port)
        require_response(apache_port, f"{prefix}/api/status", contains=b"connections", headers=auth)
        differential_benchmark(
            frontend_port,
            apache_port,
            f"{prefix}/api/status",
            context.artifact_dir / "apache-vapache-benchmark.json",
            headers=(f"Authorization: token {TOKEN}",),
        )
