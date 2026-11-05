"""Exercise authenticated WebDAV and large uploads through Nextcloud/PHP-FPM."""

from __future__ import annotations

import grp
import json
import os
from pathlib import Path

from lib import (
    CaseContext,
    DeploymentError,
    basic_authorization,
    common_apache_config,
    common_vapache_config,
    differential_benchmark,
    free_port,
    request,
    require_response,
    start_apache,
    start_vapache,
    service_identity,
    wait_for_path,
)


HERE = Path(__file__).resolve().parent
PHP_UID = 82
PHP_GID = 82
PASSWORD = "vapache-nextcloud-password-42"


def verify_installation(compose, nextcloud_root: Path, stage: str, *, occ_user: int) -> None:
    """Fail before HTTP dispatch if Nextcloud or its dual mount is inconsistent."""
    output = compose.exec(
        "nextcloud",
        ["php", "occ", "status", "--output=json"],
        user=str(occ_user),
    )
    try:
        status = json.loads(output)
    except json.JSONDecodeError as error:
        raise DeploymentError(f"Nextcloud {stage} status was not JSON: {output!r}") from error
    if status.get("installed") is not True or status.get("maintenance") is not False:
        raise DeploymentError(f"Nextcloud {stage} state is not ready: {status!r}")
    compose.exec(
        "nextcloud",
        [
            "/bin/sh",
            "-c",
            'test -f "$1/config/config.php" && '
            'cmp -s /var/www/html/config/config.php "$1/config/config.php"',
            "verify-nextcloud-mount",
            os.fspath(nextcloud_root),
        ],
        user=str(PHP_UID),
    )


def freeze_application(compose) -> None:
    compose.exec("nextcloud", ["chown", "-R", "0:0", "/var/www/html"], user="0")
    compose.exec("nextcloud", ["chmod", "-R", "a=rX", "/var/www/html"], user="0")
    compose.exec("nextcloud", ["chown", "-R", f"{PHP_UID}:{PHP_GID}", "/var/www/html/data"], user="0")
    compose.exec(
        "nextcloud",
        [
            "/bin/sh",
            "-c",
            "find /var/www/html/data -type d -exec chmod 750 {} +; "
            "find /var/www/html/data -type f -exec chmod 640 {} +",
        ],
        user="0",
    )
    compose.exec("nextcloud", ["chown", "-R", f"0:{PHP_GID}", "/var/www/html/config"], user="0")
    compose.exec("nextcloud", ["chmod", "750", "/var/www/html/config"], user="0")
    compose.exec("nextcloud", ["chmod", "640", "/var/www/html/config/config.php"], user="0")


def dav_request(
    port: int,
    path: str,
    method: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    merged = {"Authorization": basic_authorization("admin", PASSWORD)}
    merged.update(headers or {})
    return request(port, path, method=method, headers=merged, body=body, timeout=60)


def run(context: CaseContext, variant: dict[str, str]) -> None:
    nextcloud_root = context.run_dir / "nextcloud"
    php_run = context.run_dir / "php-run"
    nextcloud_root.mkdir()
    php_run.mkdir()
    os.chmod(nextcloud_root, 0o777)
    os.chmod(php_run, 0o755)
    fpm_config = context.run_dir / "fpm.conf"
    _, service_group = service_identity()
    service_gid = grp.getgrnam(service_group).gr_gid
    fpm_config.write_text((HERE / "fpm.conf").read_text().replace("DEPLOY_GID", str(service_gid)))
    compose = context.compose(
        HERE / "compose.yml",
        {
            "NEXTCLOUD_ROOT": os.fspath(nextcloud_root),
            "PHP_RUN": os.fspath(php_run),
            "FPM_CONFIG": os.fspath(fpm_config),
        },
    )
    compose.pull()
    compose.up()
    context.add_cleanup(
        lambda: compose.exec(
            "nextcloud",
            [
                "/bin/sh",
                "-c",
                f"chmod -R u+rwX /var/www/html && chown -R {os.getuid()}:{os.getgid()} /var/www/html",
            ],
            user="0",
        )
    )
    socket_path = php_run / "php-fpm.sock"
    wait_for_path(socket_path, timeout=120)
    verify_installation(compose, nextcloud_root, "before freeze", occ_user=PHP_UID)
    compose.exec(
        "nextcloud",
        [
            "php",
            "occ",
            "config:system:set",
            "config_is_read_only",
            "--type=boolean",
            "--value=true",
        ],
        user=str(PHP_UID),
    )
    freeze_application(compose)
    verify_installation(compose, nextcloud_root, "after freeze", occ_user=0)

    port = free_port()
    extra = fr"""
DirectoryIndex index.php
VapacheFastCGIStablePath On unix:{socket_path} {PHP_UID} {PHP_UID} 0 {os.getuid()}
ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:{socket_path}|fcgi://localhost{nextcloud_root}/"
<Directory "{nextcloud_root}">
    Options FollowSymLinks
    AllowOverride None
    CGIPassAuth On
    Require all granted
</Directory>
<Directory "{nextcloud_root / 'config'}">
    Require all denied
</Directory>
<Directory "{nextcloud_root / 'data'}">
    Require all denied
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</Directory>
<Directory "{nextcloud_root / 'lib'}">
    Require all denied
</Directory>
<FilesMatch "(^\.|autotest|occ|issue|indie|db_|console)">
    Require all denied
</FilesMatch>
"""
    config, pid_file = common_vapache_config(
        context.run_dir,
        port,
        nextcloud_root,
        capabilities=("FastCgi",),
        extra=extra,
    )
    server = start_vapache(context, config, pid_file, port)
    require_response(port, "/status.php", contains=b'"installed":true')

    dav_root = "/remote.php/dav/files/admin"
    directory = f"{dav_root}/vapache-integration"
    status, _, body = dav_request(port, directory, "MKCOL")
    if status not in (201, 405):
        raise DeploymentError(f"Nextcloud MKCOL failed: {status} {body[:1000]!r}")

    marker = b"nextcloud-vapache-webdav-marker\n"
    payload = marker + (b"0123456789abcdef" * (131072 if variant["upload"] == "large" else 4096))
    source = f"{directory}/source.bin"
    status, _, body = dav_request(
        port,
        source,
        "PUT",
        body=payload,
        headers={"Content-Type": "application/octet-stream"},
    )
    if status not in (201, 204):
        raise DeploymentError(f"Nextcloud upload failed: {status} {body[:1000]!r}")

    propfind_body = b'<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:getcontentlength/></d:prop></d:propfind>'
    status, _, listing = dav_request(
        port,
        directory,
        "PROPFIND",
        body=propfind_body,
        headers={"Depth": "1", "Content-Type": "application/xml"},
    )
    if status != 207 or b"source.bin" not in listing:
        raise DeploymentError(f"Nextcloud PROPFIND failed: {status} {listing[:1000]!r}")

    target = source
    if variant["dav"] == "move":
        target = f"{directory}/moved.bin"
        status, _, body = dav_request(
            port,
            source,
            "MOVE",
            headers={"Destination": f"http://127.0.0.1:{port}{target}", "Overwrite": "F"},
        )
        if status not in (201, 204):
            raise DeploymentError(f"Nextcloud MOVE failed: {status} {body[:1000]!r}")

    if variant["reload"] == "before-download":
        server.reload()
        require_response(port, "/status.php", contains=b'"installed":true')

    status, response_headers, downloaded = dav_request(port, target, "GET")
    if status != 200 or downloaded != payload:
        raise DeploymentError(
            f"Nextcloud download mismatch: status={status} length={len(downloaded)} expected={len(payload)}"
        )
    if int(response_headers.get("content-length", "0")) != len(payload):
        raise DeploymentError(f"Nextcloud download lost its length: {response_headers}")

    status, _, body = dav_request(port, target, "DELETE")
    if status != 204:
        raise DeploymentError(f"Nextcloud DELETE failed: {status} {body[:1000]!r}")

    if context.benchmark:
        apache_port = free_port()
        apache_extra = fr"""
TypesConfig /etc/mime.types
DirectoryIndex index.php
ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:{socket_path}|fcgi://localhost{nextcloud_root}/"
<Directory "{nextcloud_root}">
    Options FollowSymLinks
    AllowOverride None
    CGIPassAuth On
    Require all granted
</Directory>
<Directory "{nextcloud_root / 'config'}">
    Require all denied
</Directory>
<Directory "{nextcloud_root / 'data'}">
    Require all denied
</Directory>
<Directory "{nextcloud_root / 'lib'}">
    Require all denied
</Directory>
"""
        apache_config = common_apache_config(
            context.run_dir,
            apache_port,
            nextcloud_root,
            modules=(
                "mpm_event",
                "authz_core",
                "authz_host",
                "proxy",
                "proxy_fcgi",
                "dir",
                "mime",
            ),
            extra=apache_extra,
        )
        start_apache(context, apache_config, apache_port)
        require_response(apache_port, "/status.php", contains=b'"installed":true')
        differential_benchmark(
            port,
            apache_port,
            "/status.php",
            context.artifact_dir / "apache-vapache-benchmark.json",
        )
