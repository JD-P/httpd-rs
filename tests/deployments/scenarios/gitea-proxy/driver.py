"""Deploy Gitea and move a real Git repository through Vapache's proxy."""

from __future__ import annotations

import json
import os
import shutil
import urllib.parse
from pathlib import Path

from lib import (
    CaseContext,
    DeploymentError,
    basic_authorization,
    command,
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
GIT = Path("/usr/bin/git") if Path("/usr/bin/git").exists() else Path(shutil.which("git") or "git")
PASSWORD = "vapache-gitea-integration-42"


def write_identity_files(context: CaseContext) -> tuple[Path, Path]:
    passwd = context.run_dir / "container.passwd"
    group = context.run_dir / "container.group"
    passwd.write_text(
        "root:x:0:0:root:/root:/sbin/nologin\n"
        f"runner:x:{os.getuid()}:{os.getgid()}:Gitea integration:/data/gitea:/sbin/nologin\n"
    )
    group.write_text(f"root:x:0:\nrunner:x:{os.getgid()}:\n")
    os.chmod(passwd, 0o644)
    os.chmod(group, 0o644)
    return passwd, group


def write_config(data: Path, root_url: str, prefix: str) -> None:
    for directory in (data / "conf", data / "repositories", data / "sessions", data / "avatars"):
        directory.mkdir(parents=True, exist_ok=True)
    container_data = Path("/data/gitea")
    (data / "conf/app.ini").write_text(
        f"""APP_NAME = Vapache Gitea Integration
RUN_USER = runner
RUN_MODE = prod

[database]
DB_TYPE = sqlite3
PATH = {container_data}/gitea.db

[repository]
ROOT = {container_data}/repositories

[server]
PROTOCOL = http
HTTP_ADDR = 0.0.0.0
HTTP_PORT = 3000
DOMAIN = 127.0.0.1
ROOT_URL = {root_url}
SERVE_FROM_SUB_PATH = {'true' if prefix else 'false'}
DISABLE_SSH = true
LFS_START_SERVER = false

[security]
INSTALL_LOCK = true
SECRET_KEY = vapache-gitea-integration-secret-key-not-for-production

[service]
DISABLE_REGISTRATION = true
REQUIRE_SIGNIN_VIEW = false

[session]
PROVIDER = file
PROVIDER_CONFIG = {container_data}/sessions

[picture]
AVATAR_UPLOAD_PATH = {container_data}/avatars

[log]
MODE = console
LEVEL = Warn
ROOT_PATH = /tmp
"""
    )


def create_admin(compose) -> None:
    output = compose.exec(
        "gitea",
        [
            "/usr/local/bin/gitea",
            "admin",
            "user",
            "create",
            "--config",
            "/data/gitea/conf/app.ini",
            "--username",
            "admin",
            "--password",
            PASSWORD,
            "--email",
            "integration@vapache.invalid",
            "--admin",
            "--must-change-password=false",
        ],
    )
    if "created" not in output.lower() and "already exists" not in output.lower():
        raise DeploymentError(f"Gitea administrator creation failed: {output}")


def create_repository(port: int, prefix: str, authorization: str) -> None:
    body = json.dumps(
        {"name": "integration", "description": "Vapache smart HTTP integration", "private": False}
    ).encode()
    status, _, response = request(
        port,
        f"{prefix}/api/v1/user/repos",
        method="POST",
        headers={"Authorization": authorization, "Content-Type": "application/json"},
        body=body,
    )
    if status not in (201, 409):
        raise DeploymentError(f"Gitea repository API failed with {status}: {response[:1000]!r}")


def transfer_repository(context: CaseContext, port: int, prefix: str, authorization: str) -> None:
    source = context.run_dir / "gitea-source"
    clone = context.run_dir / "gitea-clone"
    source.mkdir()
    command([GIT, "init", "--initial-branch=main"], cwd=source)
    (source / "README.md").write_text("gitea-vapache-smart-http-marker\n")
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Vapache Integration",
            "GIT_AUTHOR_EMAIL": "integration@vapache.invalid",
            "GIT_COMMITTER_NAME": "Vapache Integration",
            "GIT_COMMITTER_EMAIL": "integration@vapache.invalid",
        }
    )
    command([GIT, "add", "README.md"], cwd=source, env=environment)
    command([GIT, "commit", "-m", "proxy transfer fixture"], cwd=source, env=environment)
    repository_url = f"http://127.0.0.1:{port}{prefix}/admin/integration.git"
    command([GIT, "remote", "add", "origin", repository_url], cwd=source)
    auth_option = f"http.extraHeader=Authorization: {authorization}"
    command([GIT, "-c", auth_option, "push", "origin", "main"], cwd=source, timeout=120)
    command([GIT, "-c", auth_option, "clone", repository_url, os.fspath(clone)], timeout=120)
    if (clone / "README.md").read_text() != "gitea-vapache-smart-http-marker\n":
        raise DeploymentError("Gitea smart-HTTP clone did not reproduce the pushed repository")


def run(context: CaseContext, variant: dict[str, str]) -> None:
    backend_port = free_port()
    frontend_port = free_port()
    prefix = "/gitea" if variant["mount"] == "subpath" else ""
    root_url = f"http://127.0.0.1:{frontend_port}{prefix}/"
    data = context.run_dir / "gitea-data"
    data.mkdir()
    write_config(data, root_url, prefix)
    passwd, group = write_identity_files(context)
    compose = context.compose(
        HERE / "compose.yml",
        {
            "HOST_UID": str(os.getuid()),
            "HOST_GID": str(os.getgid()),
            "GITEA_DATA": os.fspath(data),
            "GITEA_PASSWD": os.fspath(passwd),
            "GITEA_GROUP": os.fspath(group),
            "GITEA_PORT": str(backend_port),
            "GITEA_HEALTH_PATH": prefix,
        },
    )
    compose.pull()
    compose.up(wait_timeout=360)
    backend_host = compose.service_ip("gitea")
    create_admin(compose)

    empty_docroot = context.run_dir / "empty"
    empty_docroot.mkdir()
    os.chmod(empty_docroot, 0o755)
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
    require_response(frontend_port, f"{prefix}/api/v1/version", contains=b"version")
    root_status, root_headers, root_body = request(frontend_port, f"{prefix}/")
    if root_status in (301, 302, 303, 307, 308):
        location = root_headers.get("location", "")
        if str(backend_port) in location:
            raise DeploymentError(f"Gitea redirect leaked its backend authority: {location}")
        redirect = urllib.parse.urlsplit(location)
        require_response(frontend_port, redirect.path or f"{prefix}/", contains=b"Gitea")
    elif root_status != 200 or b"Gitea" not in root_body:
        raise DeploymentError(f"unexpected Gitea root response: {root_status} {root_headers}")

    authorization = basic_authorization("admin", PASSWORD)
    create_repository(frontend_port, prefix, authorization)
    if variant["reload"] == "before-transfer":
        server.reload()
        require_response(frontend_port, f"{prefix}/api/v1/version", contains=b"version")
    transfer_repository(context, frontend_port, prefix, authorization)

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
            modules=(
                "mpm_event",
                "authz_core",
                "authz_host",
                "proxy",
                "proxy_http",
            ),
            extra=apache_extra,
        )
        start_apache(context, apache_config, apache_port)
        host = f"127.0.0.1:{frontend_port}"
        require_response(
            apache_port,
            f"{prefix}/api/v1/version",
            contains=b"version",
            headers={"Host": host},
        )
        benchmark_path = (
            f"{prefix}/api/v1/repos/admin/integration"
            if variant["benchmark"] == "repository"
            else f"{prefix}/api/v1/version"
        )
        differential_benchmark(
            frontend_port,
            apache_port,
            benchmark_path,
            context.artifact_dir / "apache-vapache-benchmark.json",
            headers=(f"Host: {host}", f"Authorization: {authorization}"),
            connections=4,
        )

