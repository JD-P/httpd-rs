"""Exercise AWS Signature V4 and aws-chunked object bodies through httpd-rs."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import urllib.parse
from pathlib import Path

from lib import (
    CaseContext,
    DeploymentError,
    common_apache_config,
    common_httpd_rs_config,
    differential_benchmark,
    free_port,
    request,
    require_response,
    start_apache,
    start_httpd_rs,
    wait_http,
)


HERE = Path(__file__).resolve().parent
ACCESS_KEY = "httpd-rs-minio-admin"
SECRET_KEY = "httpd-rs-minio-secret-password-42"
REGION = "us-east-1"
SERVICE = "s3"
STREAMING_HASH = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def sign(key: bytes, value: str) -> bytes:
    return hmac.new(key, value.encode(), hashlib.sha256).digest()


def signing_key(date: str) -> bytes:
    key = sign(("AWS4" + SECRET_KEY).encode(), date)
    key = sign(key, REGION)
    key = sign(key, SERVICE)
    return sign(key, "aws4_request")


def canonical_query(query: str) -> str:
    fields = urllib.parse.parse_qsl(query, keep_blank_values=True)
    encoded = [
        (urllib.parse.quote(key, safe="-_.~"), urllib.parse.quote(value, safe="-_.~"))
        for key, value in fields
    ]
    return "&".join(f"{key}={value}" for key, value in sorted(encoded))


def authorization(
    method: str,
    path: str,
    query: str,
    host: str,
    payload_hash: str,
    extra_headers: dict[str, str],
) -> tuple[dict[str, str], str, str, bytes]:
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    headers = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
    headers.update({name.lower(): value.strip() for name, value in extra_headers.items()})
    signed_names = ";".join(sorted(headers))
    canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in sorted(headers))
    canonical_request = "\n".join(
        (
            method,
            urllib.parse.quote(path, safe="/-_.~"),
            canonical_query(query),
            canonical_headers,
            signed_names,
            payload_hash,
        )
    )
    scope = f"{date}/{REGION}/{SERVICE}/aws4_request"
    string_to_sign = "\n".join(
        (
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        )
    )
    key = signing_key(date)
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    outgoing = {name.title(): value for name, value in headers.items() if name != "host"}
    outgoing["Host"] = host
    outgoing["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope},"
        f"SignedHeaders={signed_names},Signature={signature}"
    )
    return outgoing, amz_date, scope, key


def aws_chunked_body(payload: bytes, amz_date: str, scope: str, key: bytes, seed: str) -> bytes:
    output = bytearray()
    previous = seed
    for offset in range(0, len(payload), 64 * 1024):
        chunk = payload[offset : offset + 64 * 1024]
        string_to_sign = "\n".join(
            (
                "AWS4-HMAC-SHA256-PAYLOAD",
                amz_date,
                scope,
                previous,
                EMPTY_HASH,
                hashlib.sha256(chunk).hexdigest(),
            )
        )
        previous = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        output.extend(f"{len(chunk):x};chunk-signature={previous}\r\n".encode())
        output.extend(chunk)
        output.extend(b"\r\n")
    final_to_sign = "\n".join(
        ("AWS4-HMAC-SHA256-PAYLOAD", amz_date, scope, previous, EMPTY_HASH, EMPTY_HASH)
    )
    final_signature = hmac.new(key, final_to_sign.encode(), hashlib.sha256).hexdigest()
    output.extend(f"0;chunk-signature={final_signature}\r\n\r\n".encode())
    return bytes(output)


def signed_request(
    port: int,
    method: str,
    path: str,
    *,
    query: str = "",
    body: bytes = b"",
    streaming: bool = False,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    host = f"127.0.0.1:{port}"
    extra = dict(headers or {})
    payload_hash = hashlib.sha256(body).hexdigest()
    wire_body = body
    if streaming:
        payload_hash = STREAMING_HASH
        extra["content-encoding"] = "aws-chunked"
        extra["x-amz-decoded-content-length"] = str(len(body))
    signed, amz_date, scope, key = authorization(
        method, path, query, host, payload_hash, extra
    )
    if streaming:
        seed = signed["Authorization"].rsplit("Signature=", 1)[1]
        wire_body = aws_chunked_body(body, amz_date, scope, key, seed)
    signed.update({name.title(): value for name, value in extra.items()})
    target = path + (f"?{query}" if query else "")
    return request(port, target, method=method, headers=signed, body=wire_body, timeout=60)


def require_s3_status(
    response: tuple[int, dict[str, str], bytes], accepted: tuple[int, ...], operation: str
) -> tuple[dict[str, str], bytes]:
    status, headers, body = response
    if status not in accepted:
        raise DeploymentError(f"MinIO {operation} failed: {status} {body[:2000]!r}")
    return headers, body


def run(context: CaseContext, variant: dict[str, str]) -> None:
    frontend_port = free_port()
    compose = context.compose(
        HERE / "compose.yml",
        {
            "MINIO_ROOT_USER": ACCESS_KEY,
            "MINIO_ROOT_PASSWORD": SECRET_KEY,
        },
    )
    compose.pull()
    compose.up()
    backend_host = compose.service_ip("minio")
    wait_http(
        9000,
        "/minio/health/live",
        timeout=120,
        host=backend_host,
        statuses=(200,),
    )

    empty_docroot = context.run_dir / "empty"
    empty_docroot.mkdir()
    backend_route = f"http://{backend_host}:9000/"
    extra = f"""
ProxyPreserveHost On
ProxyPass / {backend_route}
ProxyPassReverse / {backend_route}
"""
    config, pid_file = common_httpd_rs_config(
        context.run_dir, frontend_port, empty_docroot, extra=extra
    )
    server = start_httpd_rs(context, config, pid_file, frontend_port)
    require_response(frontend_port, "/minio/health/live", contains=b"")

    bucket = "httpd-rs-integration"
    object_name = "signed/object.bin"
    object_path = f"/{bucket}/{object_name}"
    require_s3_status(signed_request(frontend_port, "PUT", f"/{bucket}"), (200,), "bucket creation")
    marker = b"minio-httpd-rs-sigv4-marker\n"
    payload = marker + bytes(range(256)) * 4096
    require_s3_status(
        signed_request(
            frontend_port,
            "PUT",
            object_path,
            body=payload,
            streaming=variant["payload"] == "streaming",
            headers={"content-type": "application/octet-stream"},
        ),
        (200,),
        "object upload",
    )

    if variant["reload"] == "before-read":
        server.reload()
        require_response(frontend_port, "/minio/health/live", contains=b"")

    _, downloaded = require_s3_status(
        signed_request(frontend_port, "GET", object_path), (200,), "object download"
    )
    if downloaded != payload:
        raise DeploymentError(
            f"MinIO object changed through the proxy: {len(downloaded)} != {len(payload)}"
        )
    range_headers, ranged = require_s3_status(
        signed_request(
            frontend_port,
            "GET",
            object_path,
            headers={"range": "bytes=13-268"},
        ),
        (206,),
        "range download",
    )
    if ranged != payload[13:269] or "content-range" not in range_headers:
        raise DeploymentError(f"MinIO range response was corrupted: {range_headers}")

    if variant["operation"] == "listing":
        _, listing = require_s3_status(
            signed_request(frontend_port, "GET", f"/{bucket}", query="list-type=2"),
            (200,),
            "bucket listing",
        )
        if object_name.encode() not in listing:
            raise DeploymentError(f"MinIO listing omitted {object_name}: {listing[:2000]!r}")

    require_s3_status(signed_request(frontend_port, "DELETE", object_path), (204,), "object deletion")
    require_s3_status(signed_request(frontend_port, "DELETE", f"/{bucket}"), (204,), "bucket deletion")

    if context.benchmark:
        apache_port = free_port()
        apache_extra = f"""
ProxyPreserveHost On
ProxyPass / {backend_route}
ProxyPassReverse / {backend_route}
"""
        apache_config = common_apache_config(
            context.run_dir,
            apache_port,
            empty_docroot,
            modules=("mpm_event", "authz_core", "authz_host", "proxy", "proxy_http"),
            extra=apache_extra,
        )
        start_apache(context, apache_config, apache_port)
        require_response(apache_port, "/minio/health/live", contains=b"")
        differential_benchmark(
            frontend_port,
            apache_port,
            "/minio/health/live",
            context.artifact_dir / "apache-httpd-rs-benchmark.json",
            connections=4,
        )
