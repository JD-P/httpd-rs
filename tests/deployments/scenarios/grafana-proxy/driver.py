"""Run Grafana behind Vapache and validate HTTP plus bidirectional WebSockets."""

from __future__ import annotations

import base64
import hashlib
import socket
import struct
import time
import urllib.parse
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
)


HERE = Path(__file__).resolve().parent


def read_exact(stream: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise DeploymentError("WebSocket closed during a frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_masked_frame(stream: socket.socket, opcode: int, payload: bytes) -> None:
    mask = b"vp42"
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
    if second & 0x80:
        mask = read_exact(stream, 4)
        payload = read_exact(stream, length)
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    else:
        payload = read_exact(stream, length)
    return opcode, payload


def open_websocket(port: int, path: str, *, authority_port: int | None = None) -> socket.socket:
    stream = socket.create_connection(("127.0.0.1", port), timeout=15)
    stream.settimeout(15)
    key = base64.b64encode(b"vapache-grafana!").decode()
    authority_port = authority_port or port
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{authority_port}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Origin: http://127.0.0.1:{authority_port}\r\n\r\n"
    ).encode()
    stream.sendall(request)
    response = bytearray()
    while b"\r\n\r\n" not in response and len(response) <= 65536:
        # Avoid consuming any first WebSocket frame coalesced with the 101.
        chunk = stream.recv(1)
        if not chunk:
            break
        response.extend(chunk)
    status_line = bytes(response).split(b"\r\n", 1)[0]
    if b" 101 " not in status_line:
        stream.close()
        raise DeploymentError(f"Grafana WebSocket upgrade failed: {bytes(response[:1000])!r}")
    response_headers: dict[bytes, bytes] = {}
    for line in bytes(response).split(b"\r\n")[1:]:
        if b":" in line:
            name, value = line.split(b":", 1)
            response_headers[name.strip().lower()] = value.strip()
    expected_accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    )
    if response_headers.get(b"sec-websocket-accept") != expected_accept:
        stream.close()
        raise DeploymentError(f"Grafana WebSocket accept mismatch: {response_headers}")
    return stream


def expect_pong(stream: socket.socket) -> None:
    send_masked_frame(stream, 0x9, b"vapache-ping")
    for _ in range(8):
        opcode, payload = read_frame(stream)
        if opcode == 0xA and payload == b"vapache-ping":
            return
        if opcode == 0x9:
            send_masked_frame(stream, 0xA, payload)
        if opcode == 0x8:
            raise DeploymentError(f"Grafana closed the WebSocket before pong: {payload!r}")
    raise DeploymentError("Grafana did not return the WebSocket ping payload")


def run(context: CaseContext, variant: dict[str, str]) -> None:
    backend_port = free_port()
    frontend_port = free_port()
    prefix = "/grafana" if variant["mount"] == "subpath" else ""
    root_url = f"http://127.0.0.1:{frontend_port}{prefix}/"
    compose = context.compose(
        HERE / "compose.yml",
        {
            "GRAFANA_PORT": str(backend_port),
            "GRAFANA_ROOT_URL": root_url,
            "GRAFANA_SUBPATH": "true" if prefix else "false",
            "GRAFANA_HEALTH_PATH": prefix,
        },
    )
    compose.pull()
    compose.up()
    backend_host = compose.service_ip("grafana")

    empty_docroot = context.run_dir / "empty"
    empty_docroot.mkdir()
    route = f"{prefix}/" if prefix else "/"
    backend_route = f"http://{backend_host}:3000{route}"
    extra = f"""
ProxyPass {route} {backend_route}
ProxyPassReverse {route} {backend_route}
"""
    config, pid_file = common_vapache_config(
        context.run_dir, frontend_port, empty_docroot, extra=extra
    )
    server = start_vapache(context, config, pid_file, frontend_port)
    require_response(frontend_port, f"{prefix}/api/health", contains=b'"database":"ok"')
    root_status, root_headers, root_body = request(frontend_port, f"{prefix}/")
    if root_status in (301, 302, 303, 307, 308):
        location = root_headers.get("location", "")
        if str(backend_port) in location:
            raise DeploymentError(f"Grafana redirect leaked its backend authority: {location}")
        redirect_path = urllib.parse.urlsplit(location).path or f"{prefix}/"
        require_response(frontend_port, redirect_path, contains=b"Grafana")
    elif root_status != 200 or b"Grafana" not in root_body:
        raise DeploymentError(f"unexpected Grafana root response: {root_status} {root_headers}")

    websocket = open_websocket(frontend_port, f"{prefix}/api/live/ws")
    try:
        if variant["reload"] == "after-start":
            server.reload()
            time.sleep(0.5)
            server.assert_running()
        if variant["websocket"] == "message":
            expect_pong(websocket)
        send_masked_frame(websocket, 0x8, b"\x03\xe8")
    finally:
        websocket.close()

    require_response(frontend_port, f"{prefix}/api/health", contains=b'"database":"ok"')
    if context.benchmark:
        apache_port = free_port()
        websocket_route = f"{prefix}/api/live/" if prefix else "/api/live/"
        websocket_backend = f"ws://{backend_host}:3000{websocket_route}"
        apache_extra = f"""
ProxyPass {websocket_route} {websocket_backend}
ProxyPassReverse {websocket_route} {websocket_backend}
ProxyPass {route} {backend_route}
ProxyPassReverse {route} {backend_route}
"""
        apache_config = common_apache_config(
            context.run_dir,
            apache_port,
            empty_docroot,
            modules=(
                "mpm_event",
                "authz_core",
                "authz_host",
                "proxy",
                "proxy_http",
                "proxy_wstunnel",
            ),
            extra=apache_extra,
        )
        start_apache(context, apache_config, apache_port)
        host = f"127.0.0.1:{frontend_port}"
        require_response(
            apache_port,
            f"{prefix}/api/health",
            contains=b'"database":"ok"',
            headers={"Host": host},
        )
        apache_websocket = open_websocket(
            apache_port,
            f"{prefix}/api/live/ws",
            authority_port=frontend_port,
        )
        try:
            expect_pong(apache_websocket)
            send_masked_frame(apache_websocket, 0x8, b"\x03\xe8")
        finally:
            apache_websocket.close()
        differential_benchmark(
            frontend_port,
            apache_port,
            f"{prefix}/api/health",
            context.artifact_dir / "apache-vapache-benchmark.json",
            headers=(f"Host: {host}",),
            connections=4,
        )

