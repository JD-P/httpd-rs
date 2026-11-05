"""Deploy WordPress through a protected Unix PHP-FPM endpoint."""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import shutil
import urllib.parse
import urllib.request
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
    wait_for_path,
)


HERE = Path(__file__).resolve().parent


def install_wordpress(port: int) -> urllib.request.OpenerDirector:
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    install_url = f"http://127.0.0.1:{port}/wp-admin/install.php"
    with opener.open(install_url, timeout=30) as response:
        page = response.read()
    if b"WordPress" not in page:
        raise DeploymentError(f"WordPress installer did not load: {page[:500]!r}")
    form = urllib.parse.urlencode(
        {
            "weblog_title": "Vapache WordPress Integration",
            "user_name": "admin",
            "admin_password": "vapache-integration-password-42",
            "admin_password2": "vapache-integration-password-42",
            "pw_weak": "on",
            "admin_email": "integration@vapache.invalid",
            "blog_public": "0",
            "Submit": "Install WordPress",
            "language": "",
        }
    ).encode()
    request_object = urllib.request.Request(f"{install_url}?step=2", data=form, method="POST")
    with opener.open(request_object, timeout=60) as response:
        installed = response.read()
    if b"Success" not in installed and b"Log In" not in installed:
        raise DeploymentError(f"WordPress installation failed: {installed[:1000]!r}")

    login_url = f"http://127.0.0.1:{port}/wp-login.php"
    login = urllib.parse.urlencode(
        {
            "log": "admin",
            "pwd": "vapache-integration-password-42",
            "wp-submit": "Log In",
            "redirect_to": f"http://127.0.0.1:{port}/wp-admin/",
            "testcookie": "1",
        }
    ).encode()
    with opener.open(login_url, timeout=30):
        pass
    request_object = urllib.request.Request(login_url, data=login, method="POST")
    with opener.open(request_object, timeout=60) as response:
        dashboard = response.read()
    if b"Dashboard" not in dashboard and b"wp-admin" not in response.geturl().encode():
        raise DeploymentError(f"WordPress authenticated workflow failed: {dashboard[:1000]!r}")
    return opener


def upload_media(port: int, opener: urllib.request.OpenerDirector) -> str:
    with opener.open(f"http://127.0.0.1:{port}/wp-admin/media-new.php", timeout=30) as response:
        page = response.read().decode(errors="replace")
    match = re.search(r'"_wpnonce"\s*:\s*"([0-9a-z]+)"', page)
    if match is None:
        match = re.search(r'name=["\']_wpnonce["\'][^>]*value=["\']([^"\']+)', page)
    if match is None:
        raise DeploymentError("WordPress media page did not expose an upload nonce")
    nonce = match.group(1)
    boundary = "vapache-wordpress-integration-boundary"
    png = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDAT\x08\xd7c\xf8\xcf\xc0\xf0\x1f\x00\x05\x00\x01\xff\x89\x99=\x1d\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    parts: list[bytes] = []
    for name, value in (("name", "vapache-integration.png"), ("action", "upload-attachment"), ("_wpnonce", nonce)):
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode()
        )
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"async-upload\"; filename=\"vapache-integration.png\"\r\nContent-Type: image/png\r\n\r\n".encode()
        + png
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    request_object = urllib.request.Request(
        f"http://127.0.0.1:{port}/wp-admin/async-upload.php",
        data=b"".join(parts),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with opener.open(request_object, timeout=60) as response:
        uploaded = json.loads(response.read())
    if not uploaded.get("success"):
        raise DeploymentError(f"WordPress media upload failed: {uploaded}")
    try:
        return str(uploaded["data"]["url"])
    except (KeyError, TypeError) as error:
        raise DeploymentError(f"WordPress upload omitted its public URL: {uploaded}") from error


def run(context: CaseContext, variant: dict[str, str]) -> None:
    wordpress_root = context.run_dir / "wordpress"
    php_run = context.run_dir / "php-run"
    wordpress_root.mkdir()
    php_run.mkdir()
    os.chmod(wordpress_root, 0o777)
    os.chmod(php_run, 0o755)
    fpm_config = context.run_dir / "fpm.conf"
    shutil.copy2(HERE / "fpm.conf", fpm_config)
    compose = context.compose(
        HERE / "compose.yml",
        {
            "WORDPRESS_ROOT": os.fspath(wordpress_root),
            "PHP_RUN": os.fspath(php_run),
            "FPM_CONFIG": os.fspath(fpm_config),
        },
    )
    compose.pull()
    compose.up()
    context.add_cleanup(
        lambda: compose.exec(
            "wordpress",
            [
                "/bin/sh",
                "-c",
                f"chmod -R u+rwX /var/www/html && chown -R {os.getuid()}:{os.getgid()} /var/www/html",
            ],
            user="0",
        )
    )
    socket_path = php_run / "php-fpm.sock"
    wait_for_path(socket_path, timeout=60)

    # The official image populates the staging tree.  Freeze executable PHP as
    # root-owned and leave only the upload directory writable by PHP-FPM.
    compose.exec("wordpress", ["chown", "-R", f"{os.getuid()}:{os.getgid()}", "/var/www/html"], user="0")
    htaccess = wordpress_root / ".htaccess"
    htaccess.write_text(
        "RewriteEngine On\n"
        "RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\n"
        "RewriteBase /\n"
        "RewriteRule ^index\\.php$ - [L]\n"
        "RewriteCond %{REQUEST_FILENAME} !-f\n"
        "RewriteCond %{REQUEST_FILENAME} !-d\n"
        "RewriteRule . /index.php [L]\n"
    )
    os.chmod(htaccess, 0o644)
    uploads = wordpress_root / "wp-content/uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    (uploads / "must-not-execute.php").write_text("<?php echo 'upload-executed'; ?>\n")
    compose.exec("wordpress", ["chown", "-R", "0:0", "/var/www/html"], user="0")
    compose.exec("wordpress", ["chmod", "-R", "a=rX", "/var/www/html"], user="0")
    compose.exec("wordpress", ["chown", "0:33", "/var/www/html/wp-config.php"], user="0")
    compose.exec("wordpress", ["chmod", "640", "/var/www/html/wp-config.php"], user="0")
    compose.exec("wordpress", ["mkdir", "-p", "/var/www/html/wp-content/uploads"], user="0")
    compose.exec("wordpress", ["chown", "-R", "33:33", "/var/www/html/wp-content/uploads"], user="0")
    compose.exec("wordpress", ["chmod", "755", "/var/www/html/wp-content/uploads"], user="0")

    port = free_port()
    cache_root = context.run_dir / "cache"
    cache_root.mkdir()
    os.chmod(cache_root, 0o777)
    cache = ""
    if variant["asset_cache"] == "disk":
        cache = f"""
CacheRoot "{cache_root}"
CacheEnable disk /wp-includes/css/
CacheHeader On
CacheIgnoreNoLastMod On
CacheDefaultExpire 300
"""
    trusted_owner = os.getuid()
    extra = f"""
DirectoryIndex index.php
VapacheFastCGIStablePath On unix:{socket_path} 33 33 0 {trusted_owner}
ProxyPassMatch ^/(.*\\.php(/.*)?)$ "unix:{socket_path}|fcgi://localhost{wordpress_root}/"
<Directory "{wordpress_root}">
    Options FollowSymLinks
    AllowOverride FileInfo
    Require all granted
</Directory>
<Directory "{wordpress_root / 'wp-content/uploads'}">
    <FilesMatch "\\.php$">
        Require all denied
    </FilesMatch>
</Directory>
{cache}
"""
    config, pid_file = common_vapache_config(
        context.run_dir,
        port,
        wordpress_root,
        capabilities=("AccessFiles", "FastCgi"),
        extra=extra,
    )
    server = start_vapache(context, config, pid_file, port)
    opener = install_wordpress(port)
    uploaded_url = upload_media(port, opener)
    uploaded_path = urllib.parse.urlsplit(uploaded_url).path
    uploaded_status, uploaded_headers, uploaded_body = request(port, uploaded_path)
    if uploaded_status != 200 or uploaded_headers.get("content-type", "").split(";", 1)[0] != "image/png":
        raise DeploymentError(f"WordPress uploaded media was not served correctly: {uploaded_status} {uploaded_headers}")
    if not uploaded_body.startswith(b"\x89PNG"):
        raise DeploymentError("WordPress uploaded media body was corrupted")

    if variant["permalinks"] == "pretty":
        compose.exec(
            "wordpress",
            [
                "php",
                "-r",
                "require '/var/www/html/wp-load.php'; "
                "update_option('permalink_structure', '/%postname%/'); "
                "flush_rewrite_rules(false);",
            ],
            user="33",
        )
        require_response(port, "/hello-world/", contains=b"Hello world")
    else:
        require_response(port, "/?p=1", contains=b"Hello world")
    require_response(port, "/", contains=b"Vapache WordPress Integration")
    require_response(port, "/wp-json/wp/v2/posts", contains=b"hello-world")
    source_status, source_headers, source_body = request(port, "/index.php")
    source_redirect = source_headers.get("location", "")
    safe_canonical_redirect = source_status in {301, 302, 307, 308} and source_redirect == (
        f"http://127.0.0.1:{port}/"
    )
    if (source_status != 200 and not safe_canonical_redirect) or b"<?php" in source_body:
        raise DeploymentError("WordPress PHP source was exposed or index.php failed")
    require_response(port, "/wp-content/uploads/must-not-execute.php", status=403)

    asset_path = "/wp-includes/css/dashicons.min.css"
    require_response(port, asset_path, contains=b"dashicons")
    if variant["asset_cache"] == "disk":
        request(port, asset_path)
        cached_headers, _ = require_response(port, asset_path)
        if cached_headers.get("x-cache", "").upper() != "HIT":
            raise DeploymentError(f"WordPress static asset did not enter the cache: {cached_headers}")

    if variant["reload"] == "after-start":
        server.reload()
        require_response(port, "/wp-json/", contains=b"WordPress")
    if context.benchmark:
        apache_port = free_port()
        apache_cache = context.run_dir / "apache-cache"
        apache_cache.mkdir()
        os.chmod(apache_cache, 0o777)
        apache_cache_config = ""
        apache_modules = [
            "mpm_event",
            "authz_core",
            "authz_host",
            "proxy",
            "proxy_fcgi",
            "dir",
            "mime",
            "rewrite",
        ]
        if variant["asset_cache"] == "disk":
            apache_modules.extend(["cache", "cache_disk"])
            apache_cache_config = f"""
CacheRoot "{apache_cache}"
CacheEnable disk /wp-includes/css/
CacheHeader On
CacheIgnoreNoLastMod On
CacheDefaultExpire 300
"""
        apache_extra = f"""
TypesConfig /etc/mime.types
DirectoryIndex index.php
ProxyPassMatch ^/(.*\\.php(/.*)?)$ "unix:{socket_path}|fcgi://localhost{wordpress_root}/"
<Directory "{wordpress_root}">
    Options FollowSymLinks
    AllowOverride FileInfo
    Require all granted
</Directory>
<Directory "{wordpress_root / 'wp-content/uploads'}">
    <FilesMatch "\\.php$">
        Require all denied
    </FilesMatch>
</Directory>
{apache_cache_config}
"""
        apache_config = common_apache_config(
            context.run_dir,
            apache_port,
            wordpress_root,
            modules=apache_modules,
            extra=apache_extra,
        )
        start_apache(context, apache_config, apache_port)
        host = f"127.0.0.1:{port}"
        require_response(apache_port, "/", contains=b"Vapache WordPress Integration", headers={"Host": host})
        differential_benchmark(
            port,
            apache_port,
            "/",
            context.artifact_dir / "apache-vapache-benchmark.json",
            headers=(f"Host: {host}",),
            connections=4,
        )

