"""Build the pinned Bakery Demo and exercise Gunicorn through Vapache."""

from __future__ import annotations

import http.cookies
import json
import os
import re
import shutil
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
    stage_verified_tarball,
    start_apache,
    start_vapache,
    wait_http,
)


HERE = Path(__file__).resolve().parent
SOURCE_URL = (
    "https://codeload.github.com/wagtail/bakerydemo/tar.gz/"
    "890285b95dcf980215ab9e9942d64ed2b47c48c3"
)
SOURCE_SHA256 = "7f9aaff37ff240df20f0a14d5d084f49026b62aaca5d0440decff265c14e3e0a"
ADMIN_PASSWORD = "vapache-wagtail-password-42"


def cookie_value(header: str, name: str) -> str:
    jar = http.cookies.SimpleCookie()
    jar.load(header)
    if name not in jar:
        raise DeploymentError(f"Wagtail response omitted the {name} cookie")
    return jar[name].value


def admin_login(port: int) -> str:
    status, headers, body = request(port, "/admin/login/")
    if status != 200:
        raise DeploymentError(f"Wagtail login form failed: {status} {body[:1000]!r}")
    csrf_cookie = cookie_value(headers.get("set-cookie", ""), "csrftoken")
    match = re.search(br'name="csrfmiddlewaretoken" value="([^"]+)"', body)
    if match is None:
        raise DeploymentError("Wagtail login form omitted its CSRF token")
    form = urllib.parse.urlencode(
        {
            "csrfmiddlewaretoken": match.group(1).decode(),
            "username": "admin",
            "password": ADMIN_PASSWORD,
            "next": "/admin/",
        }
    ).encode()
    status, response_headers, response = request(
        port,
        "/admin/login/",
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": f"csrftoken={csrf_cookie}",
            "Referer": f"http://127.0.0.1:{port}/admin/login/",
        },
        body=form,
    )
    if status != 302 or response_headers.get("location") != "/admin/":
        raise DeploymentError(
            f"Wagtail admin login failed: {status} {response_headers} {response[:1000]!r}"
        )
    session = cookie_value(response_headers.get("set-cookie", ""), "sessionid")
    return f"csrftoken={csrf_cookie}; sessionid={session}"


def run(context: CaseContext, variant: dict[str, str]) -> None:
    build = context.run_dir / "build"
    build.mkdir()
    stage_verified_tarball(SOURCE_URL, SOURCE_SHA256, build / "app")
    shutil.copy2(HERE / "Dockerfile", build / "Dockerfile")
    shutil.copy2(HERE / "requirements.lock", build / "requirements.lock")
    image = context.build_staged_image(build, build / "Dockerfile", label="wagtail")

    media = context.run_dir / "media"
    media.mkdir()
    os.chmod(media, 0o777)
    compose = context.compose(
        HERE / "compose.yml",
        {
            "WAGTAIL_IMAGE": image,
            "WAGTAIL_MEDIA": os.fspath(media),
            "WAGTAIL_WORKERS": "1" if variant["workers"] == "one" else "2",
        },
        local_images=(image,),
    )
    compose.pull()
    compose.up()
    backend_host = compose.service_ip("wagtail")
    # A direct probe uses the private container IP as Host; Django correctly
    # rejects that untrusted name with 400 once the application is ready. The
    # Vapache-facing checks below use an allowed public Host and must be 200.
    wait_http(8000, "/", timeout=240, host=backend_host, statuses=(200, 400))

    document_root = context.run_dir / "empty"
    document_root.mkdir()
    port = free_port()
    backend = f"http://{backend_host}:8000/"
    # Django validates the public authority. Preserve it rather than exposing
    # the ephemeral private container IP as the application-facing Host.
    extra = (
        "ProxyPreserveHost On\n"
        f"ProxyPass / {backend}\n"
        f"ProxyPassReverse / {backend}\n"
    )
    config, pid_file = common_vapache_config(context.run_dir, port, document_root, extra=extra)
    server = start_vapache(context, config, pid_file, port)
    require_response(port, "/", contains=b"The Wagtail Bakery")

    status, _, api_body = request(port, "/api/v2/pages/?limit=2")
    if status != 200:
        raise DeploymentError(f"Wagtail page API failed: {status} {api_body[:1000]!r}")
    try:
        api = json.loads(api_body)
    except json.JSONDecodeError as error:
        raise DeploymentError(f"Wagtail page API was not JSON: {api_body[:1000]!r}") from error
    if not api.get("items") or int(api.get("meta", {}).get("total_count", 0)) < 2:
        raise DeploymentError(f"Wagtail page API omitted fixture content: {api!r}")

    cookie = admin_login(port)
    require_response(port, "/admin/", contains=b"Dashboard", headers={"Cookie": cookie})
    if variant["workflow"] == "api":
        require_response(port, "/api/v2/pages/?limit=2", contains=b'"items"')
    else:
        require_response(port, "/admin/pages/", contains=b"Pages", headers={"Cookie": cookie})

    if variant["reload"] == "after-login":
        server.reload()
        require_response(port, "/admin/", contains=b"Dashboard", headers={"Cookie": cookie})

    if context.benchmark:
        apache_port = free_port()
        apache_config = common_apache_config(
            context.run_dir,
            apache_port,
            document_root,
            modules=("mpm_event", "authz_core", "authz_host", "proxy", "proxy_http"),
            extra=extra,
        )
        start_apache(context, apache_config, apache_port)
        require_response(apache_port, "/", contains=b"The Wagtail Bakery")
        differential_benchmark(
            port,
            apache_port,
            "/",
            context.artifact_dir / "apache-vapache-benchmark.json",
            connections=2,
        )
