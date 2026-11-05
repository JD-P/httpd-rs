"""Exercise a current Jenkins LTS instance through root and subpath proxies."""

from __future__ import annotations

import base64
import json
import shutil
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
AUTHORIZATION = "Basic " + base64.b64encode(
    b"vapache:vapache-jenkins-password-42"
).decode("ascii")


def authenticated_request(
    port: int,
    path: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
):
    request_headers = {"Authorization": AUTHORIZATION}
    request_headers.update(headers or {})
    return request(port, path, method=method, headers=request_headers, body=body)


def create_job(port: int, prefix: str) -> None:
    status, response_headers, body = authenticated_request(
        port, f"{prefix}/crumbIssuer/api/json"
    )
    if status != 200:
        raise DeploymentError(f"Jenkins crumb request failed: {status} {body[:1000]!r}")
    try:
        crumb = json.loads(body)
        field = crumb["crumbRequestField"]
        value = crumb["crumb"]
    except (KeyError, TypeError, ValueError) as error:
        raise DeploymentError(f"Jenkins returned a malformed crumb: {body[:1000]!r}") from error
    session_cookie = response_headers.get("set-cookie", "").split(";", 1)[0]
    if not session_cookie:
        raise DeploymentError("Jenkins crumb response omitted its session cookie")
    job = b"""<?xml version="1.0" encoding="UTF-8"?>
<project>
  <description>Created through the Vapache deployment integration</description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <scm class="hudson.scm.NullSCM"/>
  <canRoam>true</canRoam>
  <disabled>false</disabled>
  <blockBuildWhenDownstreamBuilding>false</blockBuildWhenDownstreamBuilding>
  <blockBuildWhenUpstreamBuilding>false</blockBuildWhenUpstreamBuilding>
  <triggers/>
  <concurrentBuild>false</concurrentBuild>
  <builders/>
  <publishers/>
  <buildWrappers/>
</project>
"""
    status, _, response = authenticated_request(
        port,
        f"{prefix}/createItem?name=vapache-integration",
        method="POST",
        headers={
            "Content-Type": "application/xml",
            "Cookie": session_cookie,
            field: value,
        },
        body=job,
    )
    if status not in (200, 201, 302):
        raise DeploymentError(f"Jenkins job creation failed: {status} {response[:1000]!r}")
    require_response(
        port,
        f"{prefix}/job/vapache-integration/api/json",
        contains=b"Vapache deployment integration",
        headers={"Authorization": AUTHORIZATION},
    )


def run(context: CaseContext, variant: dict[str, str]) -> None:
    frontend_port = free_port()
    prefix = "/jenkins" if variant["mount"] == "subpath" else ""
    init_script = context.run_dir / "jenkins-security.groovy"
    shutil.copy2(HERE / "security.groovy", init_script)
    compose = context.compose(
        HERE / "compose.yml",
        {
            "JENKINS_PREFIX": prefix,
            "JENKINS_INIT": str(init_script),
        },
    )
    compose.pull()
    compose.up()
    backend_host = compose.service_ip("jenkins")
    wait_http(
        8080,
        f"{prefix}/login",
        timeout=180,
        host=backend_host,
        statuses=(200,),
    )

    empty_docroot = context.run_dir / "empty"
    empty_docroot.mkdir()
    route = f"{prefix}/" if prefix else "/"
    backend_route = f"http://{backend_host}:8080{route}"
    extra = f"""
ProxyPass {route} {backend_route}
ProxyPassReverse {route} {backend_route}
"""
    config, pid_file = common_vapache_config(
        context.run_dir, frontend_port, empty_docroot, extra=extra
    )
    server = start_vapache(context, config, pid_file, frontend_port)
    require_response(frontend_port, f"{prefix}/login", contains=b"Jenkins")
    create_job(frontend_port, prefix)

    if variant["reload"] == "after-start":
        server.reload()
        require_response(
            frontend_port,
            f"{prefix}/job/vapache-integration/api/json",
            contains=b"Vapache deployment integration",
            headers={"Authorization": AUTHORIZATION},
        )

    if context.benchmark:
        apache_port = free_port()
        apache_config = common_apache_config(
            context.run_dir,
            apache_port,
            empty_docroot,
            modules=("mpm_event", "authz_core", "authz_host", "proxy", "proxy_http"),
            extra=extra,
        )
        start_apache(context, apache_config, apache_port)
        benchmark_path = (
            f"{prefix}/job/vapache-integration/api/json"
            if variant["benchmark"] == "job"
            else f"{prefix}/login"
        )
        expected = b"Vapache deployment integration" if variant["benchmark"] == "job" else b"Jenkins"
        benchmark_headers = {"Authorization": AUTHORIZATION} if variant["benchmark"] == "job" else None
        require_response(apache_port, benchmark_path, contains=expected, headers=benchmark_headers)
        differential_benchmark(
            frontend_port,
            apache_port,
            benchmark_path,
            context.artifact_dir / "apache-vapache-benchmark.json",
            headers=(f"Authorization: {AUTHORIZATION}",) if benchmark_headers else (),
            connections=2,
        )
