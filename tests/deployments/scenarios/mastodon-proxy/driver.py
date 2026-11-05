"""Exercise Mastodon's web, job, database and authenticated streaming tiers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
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
    wait_http,
)


HERE = Path(__file__).resolve().parent
PUBLIC_HOST = "deployment.test"
ACCOUNT_EMAIL = "integration@deployment.test"


def read_exact(stream: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    while count:
        chunk = stream.recv(count)
        if not chunk:
            raise DeploymentError("Mastodon WebSocket closed during a frame")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def send_frame(stream: socket.socket, opcode: int, payload: bytes) -> None:
    mask = b"vp42"
    length = len(payload)
    if length < 126:
        header = bytes((0x80 | opcode, 0x80 | length))
    elif length <= 0xFFFF:
        header = bytes((0x80 | opcode, 0xFE)) + struct.pack("!H", length)
    else:
        header = bytes((0x80 | opcode, 0xFF)) + struct.pack("!Q", length)
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    stream.sendall(header + mask + masked)


def read_frame(stream: socket.socket) -> tuple[int, bytes]:
    first, second = read_exact(stream, 2)
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
    return first & 0x0F, payload


def open_stream(port: int, token: str, stream_name: str) -> socket.socket:
    connection = socket.create_connection(("127.0.0.1", port), timeout=20)
    connection.settimeout(35)
    key = base64.b64encode(b"vapache-mastodon").decode()
    handshake = (
        "GET /api/v1/streaming HTTP/1.1\r\n"
        f"Host: {PUBLIC_HOST}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Origin: http://{PUBLIC_HOST}\r\n"
        f"Authorization: Bearer {token}\r\n\r\n"
    ).encode()
    connection.sendall(handshake)
    response = bytearray()
    while b"\r\n\r\n" not in response and len(response) <= 65536:
        chunk = connection.recv(1)
        if not chunk:
            break
        response.extend(chunk)
    status_line = bytes(response).split(b"\r\n", 1)[0]
    if b" 101 " not in status_line:
        connection.close()
        raise DeploymentError(f"Mastodon WebSocket upgrade failed: {bytes(response[:1000])!r}")
    headers: dict[bytes, bytes] = {}
    for line in bytes(response).split(b"\r\n")[1:]:
        if b":" in line:
            name, value = line.split(b":", 1)
            headers[name.strip().lower()] = value.strip()
    expected = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    )
    if headers.get(b"sec-websocket-accept") != expected:
        connection.close()
        raise DeploymentError(f"Mastodon WebSocket accept mismatch: {headers}")
    subscription = json.dumps(
        {"type": "subscribe", "stream": stream_name}, separators=(",", ":")
    ).encode()
    send_frame(connection, 0x1, subscription)
    # Mastodon's protocol has no subscription acknowledgement. Give its event
    # loop a bounded opportunity to install the Redis listener before an HTTP
    # request on a separate connection publishes the test status.
    time.sleep(0.25)
    return connection


def wait_for_status(stream: socket.socket, marker: str) -> dict[str, object]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        opcode, payload = read_frame(stream)
        if opcode == 0x9:
            send_frame(stream, 0xA, payload)
            continue
        if opcode == 0x8:
            raise DeploymentError(f"Mastodon closed the streaming socket: {payload!r}")
        if opcode != 0x1:
            continue
        try:
            event = json.loads(payload)
            status = json.loads(event.get("payload", "{}"))
        except (json.JSONDecodeError, AttributeError) as error:
            raise DeploymentError(
                f"invalid Mastodon streaming event: {payload[:1000]!r}"
            ) from error
        if event.get("event") == "update" and marker in str(status.get("content", "")):
            return status
    raise DeploymentError("Mastodon did not stream the status created through Vapache")


def create_access_token(compose) -> str:
    compose.exec(
        "web",
        [
            "bin/tootctl",
            "accounts",
            "create",
            "integration",
            "--email",
            ACCOUNT_EMAIL,
            "--confirmed",
        ],
    )
    script = (
        f"user=User.find_by!(email: {ACCOUNT_EMAIL!r});"
        "app=Doorkeeper::Application.create!(name: 'Vapache integration', "
        "redirect_uri: 'urn:ietf:wg:oauth:2.0:oob', scopes: 'read write');"
        "token=Doorkeeper::AccessToken.create!(application_id: app.id, "
        "resource_owner_id: user.id, scopes: 'read write');"
        "puts token.token"
    )
    output = compose.exec("web", ["bundle", "exec", "rails", "runner", script])
    candidates = re.findall(r"(?m)^[A-Za-z0-9_-]{32,}$", output)
    if not candidates:
        raise DeploymentError(f"Mastodon did not emit an OAuth token: {output[-1000:]!r}")
    return candidates[-1]


def run(context: CaseContext, variant: dict[str, str]) -> None:
    media = context.run_dir / "media"
    media.mkdir()
    os.chmod(media, 0o777)
    compose = context.compose(
        HERE / "compose.yml",
        {
            "MASTODON_MEDIA": os.fspath(media),
            "MASTODON_WORKERS": "1" if variant["workers"] == "one" else "2",
        },
    )
    compose.pull()
    # The first boot applies the complete production schema. Keep the generic
    # harness's short failure bound for other applications while allowing this
    # deliberately large manual topology enough time on a cold runner.
    compose.up(wait_timeout=300)
    web_host = compose.service_ip("web")
    streaming_host = compose.service_ip("streaming")
    wait_http(3000, "/health", timeout=300, host=web_host, statuses=(200,))
    wait_http(
        4000,
        "/api/v1/streaming/health",
        timeout=120,
        host=streaming_host,
        statuses=(200,),
    )
    token = create_access_token(compose)

    document_root = context.run_dir / "empty"
    document_root.mkdir()
    port = free_port()
    extra = f"""
ProxyPreserveHost On
ProxyPass /api/v1/streaming http://{streaming_host}:4000/api/v1/streaming
ProxyPassReverse /api/v1/streaming http://{streaming_host}:4000/api/v1/streaming
ProxyPass / http://{web_host}:3000/
ProxyPassReverse / http://{web_host}:3000/
"""
    config, pid_file = common_vapache_config(context.run_dir, port, document_root, extra=extra)
    server = start_vapache(context, config, pid_file, port)
    host = {"Host": PUBLIC_HOST}
    require_response(port, "/health", contains=b"OK", headers=host)
    require_response(port, "/api/v2/instance", contains=b'"domain":"deployment.test"', headers=host)
    auth = {"Host": PUBLIC_HOST, "Authorization": f"Bearer {token}"}
    require_response(
        port,
        "/api/v1/accounts/verify_credentials",
        contains=b'"username":"integration"',
        headers=auth,
    )

    stream_name = "user" if variant["stream"] == "user" else "public:local"
    websocket = open_stream(port, token, stream_name)
    try:
        if variant["reload"] == "before-publish":
            server.reload()
            time.sleep(0.5)
            server.assert_running()
            websocket.close()
            websocket = open_stream(port, token, stream_name)

        marker = f"vapache-mastodon-{variant['workers']}-{variant['stream']}"
        body = urllib.parse.urlencode({"status": marker, "visibility": "public"}).encode()
        status, _, response = request(
            port,
            "/api/v1/statuses",
            method="POST",
            headers={
                **auth,
                "Content-Type": "application/x-www-form-urlencoded",
                "Idempotency-Key": marker,
            },
            body=body,
            timeout=30,
        )
        if status != 200:
            raise DeploymentError(f"Mastodon status creation failed: {status} {response[:1000]!r}")
        try:
            created = json.loads(response)
            status_id = str(created["id"])
        except (json.JSONDecodeError, KeyError) as error:
            raise DeploymentError(
                f"invalid Mastodon status response: {response[:1000]!r}"
            ) from error
        streamed = wait_for_status(websocket, marker)
        if str(streamed.get("id")) != status_id:
            raise DeploymentError(
                f"streamed Mastodon status id {streamed.get('id')!r} did not match {status_id!r}"
            )
        require_response(
            port,
            f"/api/v1/statuses/{status_id}",
            contains=marker.encode(),
            headers=host,
        )
        deleted, _, delete_body = request(
            port,
            f"/api/v1/statuses/{status_id}",
            method="DELETE",
            headers=auth,
        )
        if deleted != 200:
            raise DeploymentError(
                f"Mastodon status cleanup failed: {deleted} {delete_body[:1000]!r}"
            )
        send_frame(websocket, 0x8, b"\x03\xe8")
    finally:
        websocket.close()

    if context.benchmark:
        apache_port = free_port()
        apache_config = common_apache_config(
            context.run_dir,
            apache_port,
            document_root,
            modules=(
                "mpm_event",
                "authz_core",
                "authz_host",
                "proxy",
                "proxy_http",
                "proxy_wstunnel",
            ),
            extra=extra,
        )
        start_apache(context, apache_config, apache_port)
        require_response(
            apache_port,
            "/api/v2/instance",
            contains=b'"domain":"deployment.test"',
            headers=host,
        )
        differential_benchmark(
            port,
            apache_port,
            "/api/v2/instance",
            context.artifact_dir / "apache-vapache-benchmark.json",
            headers=(f"Host: {PUBLIC_HOST}",),
        )
