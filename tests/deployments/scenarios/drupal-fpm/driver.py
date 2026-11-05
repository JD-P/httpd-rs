"""Install Drupal and execute its shipped .htaccess policy through PHP-FPM."""

from __future__ import annotations

import grp
import os
from pathlib import Path

from lib import (
    CaseContext,
    DeploymentError,
    command,
    common_apache_config,
    common_vapache_config,
    differential_benchmark,
    free_port,
    request,
    require_response,
    start_apache,
    start_vapache,
    service_identity,
    validate_bind_source,
    wait_for_path,
)


HERE = Path(__file__).resolve().parent
PHP_UID = 82
PHP_GID = 82


def stage_application(context: CaseContext, root: Path) -> None:
    root.mkdir()
    os.chmod(root, 0o777)
    validate_bind_source(root, context.run_dir)
    command(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--mount",
            f"type=bind,src={root},dst=/stage",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--entrypoint",
            "/bin/sh",
            context.images[0],
            "-c",
            "cp -R /opt/drupal/. /stage/",
        ],
        timeout=180,
        capture=False,
    )


def adapt_bounded_htaccess(root: Path) -> None:
    access_file = root / "web/.htaccess"
    original = access_file.read_text()
    bounded = original.replace(r"\.(?!well-known).*", r"\..*", 1)
    bounded = bounded.replace(
        r'RewriteRule "/\.|^\.(?!well-known/)" - [F]',
        'RewriteRule "^\\.well-known/" - [L]\n  RewriteRule "/\\.|^\\." - [F]',
        1,
    )
    bounded = bounded.replace("Header append Vary Accept-Encoding", "Header add Vary Accept-Encoding")
    bounded = bounded.replace("  RequestHeader unset Proxy\n", "")
    bounded = bounded.replace("AddEncoding gzip svgz\n", "")
    if (
        bounded == original
        or "(?!" in bounded
        or "Header append" in bounded
        or "RequestHeader" in bounded
        or "AddEncoding" in bounded
    ):
        raise DeploymentError("Drupal .htaccess lookaround adaptation no longer matches upstream")
    access_file.write_text(bounded)


def freeze_application(compose) -> None:
    compose.exec("drupal", ["chown", "-R", "0:0", "/opt/drupal"], user="0")
    compose.exec("drupal", ["chmod", "-R", "a=rX", "/opt/drupal"], user="0")
    compose.exec(
        "drupal", ["chown", "-R", f"{PHP_UID}:{PHP_GID}", "/opt/drupal/web/sites/default/files"], user="0"
    )
    compose.exec(
        "drupal",
        [
            "/bin/sh",
            "-c",
            "find /opt/drupal/web/sites/default/files -type d -exec chmod 755 {} +; "
            "find /opt/drupal/web/sites/default/files -type f -exec chmod 644 {} +",
        ],
        user="0",
    )


def run(context: CaseContext, variant: dict[str, str]) -> None:
    drupal_root = context.run_dir / "drupal"
    php_run = context.run_dir / "php-run"
    php_run.mkdir()
    os.chmod(php_run, 0o755)
    fpm_config = context.run_dir / "fpm.conf"
    _, service_group = service_identity()
    service_gid = grp.getgrnam(service_group).gr_gid
    fpm_config.write_text((HERE / "fpm.conf").read_text().replace("DEPLOY_GID", str(service_gid)))
    compose = context.compose(
        HERE / "compose.yml",
        {
            "DRUPAL_ROOT": os.fspath(drupal_root),
            "PHP_RUN": os.fspath(php_run),
            "FPM_CONFIG": os.fspath(fpm_config),
        },
    )
    compose.pull()
    stage_application(context, drupal_root)
    adapt_bounded_htaccess(drupal_root)
    compose.up()
    context.add_cleanup(
        lambda: compose.exec(
            "drupal",
            [
                "/bin/sh",
                "-c",
                f"chmod -R u+rwX /opt/drupal && chown -R {os.getuid()}:{os.getgid()} /opt/drupal",
            ],
            user="0",
        )
    )
    socket_path = php_run / "php-fpm.sock"
    wait_for_path(socket_path, timeout=60)

    compose.exec(
        "drupal",
        ["chmod", "-R", "a+rwX", "/opt/drupal/web/sites/default"],
        user="0",
    )
    install = compose.exec(
        "drupal",
        [
            "php",
            "-d",
            "memory_limit=512M",
            "web/core/scripts/drupal",
            "install",
            variant["profile"],
            "--site-name",
            "Vapache Drupal Integration",
            "--password",
            "vapache-drupal-password-42",
            "--no-interaction",
        ],
        user=f"{PHP_UID}:{PHP_GID}",
    )
    if not any(
        marker in install.lower()
        for marker in ("installation complete", "success", "congratulations, you installed drupal")
    ):
        raise DeploymentError(f"Drupal installer did not report success: {install[-2000:]}")
    freeze_application(compose)

    document_root = drupal_root / "web"
    port = free_port()
    extra = fr"""
LoadModule authz_core_module /vapache/builtin/mod_authz_core.so
LoadModule rewrite_module /vapache/builtin/mod_rewrite.so
LoadModule headers_module /vapache/builtin/mod_headers.so
LoadModule expires_module /vapache/builtin/mod_expires.so
LoadModule mime_module /vapache/builtin/mod_mime.so
AddEncoding gzip svgz
DirectoryIndex index.php
VapacheFastCGIStablePath On unix:{socket_path} {PHP_UID} {PHP_UID} 0 {os.getuid()}
ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:{socket_path}|fcgi://localhost{document_root}/"
<Directory "{document_root}">
    Options FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
"""
    config, pid_file = common_vapache_config(
        context.run_dir,
        port,
        document_root,
        capabilities=("AccessFiles", "FastCgi"),
        extra=extra,
    )
    server = start_vapache(context, config, pid_file, port)
    require_response(port, "/", contains=b"Vapache Drupal Integration")
    require_response(port, "/user/login", contains=b"Log in")
    # Drupal deliberately leaves core/install.php reachable after installation;
    # exercise the shipped FilesMatch denial with a genuinely private file.
    require_response(port, "/composer.json", status=403)
    hidden_status, _, hidden_body = request(port, "/.htaccess")
    if hidden_status != 403 or b"RewriteEngine" in hidden_body:
        raise DeploymentError(f"Drupal access file was exposed: {hidden_status} {hidden_body[:200]!r}")

    if variant["reload"] == "after-start":
        server.reload()
        require_response(port, "/user/login", contains=b"Log in")

    if context.benchmark:
        apache_port = free_port()
        apache_extra = fr"""
TypesConfig /etc/mime.types
DirectoryIndex index.php
ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:{socket_path}|fcgi://localhost{document_root}/"
<Directory "{document_root}">
    Options FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
"""
        apache_config = common_apache_config(
            context.run_dir,
            apache_port,
            document_root,
            modules=(
                "mpm_event",
                "authz_core",
                "authz_host",
                "proxy",
                "proxy_fcgi",
                "dir",
                "mime",
                "rewrite",
                "headers",
                "expires",
            ),
            extra=apache_extra,
        )
        start_apache(context, apache_config, apache_port)
        path = "/user/login" if variant["benchmark"] == "clean-url" else "/"
        require_response(apache_port, path, contains=b"Log in" if path != "/" else b"Vapache Drupal Integration")
        differential_benchmark(
            port,
            apache_port,
            path,
            context.artifact_dir / "apache-vapache-benchmark.json",
        )
