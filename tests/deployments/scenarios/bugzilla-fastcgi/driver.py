"""Run the pinned Bugzilla CGI application through fcgiwrap and Vapache."""

from __future__ import annotations

import http.cookiejar
import grp
import os
import re
import shutil
import stat
import urllib.parse
import urllib.request
from pathlib import Path

from lib import (
    CaseContext,
    DeploymentError,
    common_apache_config,
    common_vapache_config,
    differential_benchmark,
    download_verified_file,
    free_port,
    require_response,
    service_identity,
    stage_verified_tarball,
    start_apache,
    start_vapache,
)


HERE = Path(__file__).resolve().parent
SOURCE_URL = (
    "https://codeload.github.com/bugzilla/bugzilla/tar.gz/"
    "852cd06ef751cb5a5f87e100466e71e46e3cfc0e"
)
SOURCE_SHA256 = "d3295436a879e6f7466f67567a06b52793b450a2540e260a931564fbae05bc8d"
ADMIN_EMAIL = "admin@deployment.test"
ADMIN_PASSWORD = "vapache-bugzilla-password-42"
DBD_MARIADB_URL = "https://cpan.org/authors/id/P/PA/PALI/DBD-MariaDB-1.24.tar.gz"
DBD_MARIADB_SHA256 = "f977a25b4116a0a95a7c8a894fd37097abe19af9a6a9ed4d800604ec17873fe4"
TEMPLATE_URL = "https://cpan.org/authors/id/T/TO/TODDR/Template-Toolkit-3.106.tar.gz"
TEMPLATE_SHA256 = "c7474050be80201f1fb55f0a569b9c0ab6c1c3f0cebbd7e601bda9b4046eec85"


def login(port: int) -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(jar),
    )
    base = f"http://127.0.0.1:{port}/"
    match: re.Match[bytes] | None = None
    form = b""
    # Bugzilla's first anonymous response creates its HttpOnly login-request
    # cookie; the following request can bind a CSRF token to that cookie. A
    # browser normally receives the cookie while visiting another page first,
    # whereas this fresh integration client starts directly at the login form.
    for _ in range(2):
        with opener.open(base + "index.cgi?GoAheadAndLogIn=1", timeout=30) as response:
            form = response.read()
        match = re.search(
            br'name=["\']Bugzilla_login_token["\'][^>]*\bvalue=["\']([^"\']+)["\']',
            form,
            re.DOTALL,
        )
        if match is not None:
            break
    if match is None:
        token_at = form.find(b"Bugzilla_login_token")
        raise DeploymentError(
            "Bugzilla login form omitted its request token: "
            f"{form[max(0, token_at - 200):token_at + 500]!r}"
        )
    body = urllib.parse.urlencode(
        {
            "Bugzilla_login": ADMIN_EMAIL,
            "Bugzilla_password": ADMIN_PASSWORD,
            "Bugzilla_login_token": match.group(1).decode(),
            "GoAheadAndLogIn": "Log in",
        }
    ).encode()
    request = urllib.request.Request(base + "index.cgi", data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    with opener.open(request, timeout=30) as response:
        result = response.read()
    names = {cookie.name for cookie in jar}
    if "Bugzilla_logincookie" not in names or b"Log&nbsp;out" not in result:
        raise DeploymentError(
            f"Bugzilla did not establish an authenticated session: cookies={sorted(names)}"
        )
    return opener


def opener_contains(opener: urllib.request.OpenerDirector, url: str, marker: bytes) -> None:
    with opener.open(url, timeout=30) as response:
        body = response.read()
        status = response.status
    if status != 200 or marker not in body:
        raise DeploymentError(
            f"Bugzilla authenticated request failed: {status}, missing {marker!r}: {body[:500]!r}"
        )


def run(context: CaseContext, variant: dict[str, str]) -> None:
    bugzilla_root = context.run_dir / "bugzilla"
    stage_verified_tarball(SOURCE_URL, SOURCE_SHA256, bugzilla_root)
    fcgi_run = context.run_dir / "fcgi-run"
    fcgi_run.mkdir()
    # The container starts as root and can create the socket without making
    # its parent replaceable by either the FastCGI worker or another user.
    os.chmod(fcgi_run, 0o755)

    build = context.run_dir / "build"
    build.mkdir()
    for name in ("Dockerfile", "entrypoint.sh", "checksetup_answers.txt"):
        shutil.copy2(HERE / name, build / name)
    download_verified_file(
        DBD_MARIADB_URL,
        DBD_MARIADB_SHA256,
        build / "DBD-MariaDB-1.24.tar.gz",
        max_bytes=1024 * 1024,
    )
    download_verified_file(
        TEMPLATE_URL,
        TEMPLATE_SHA256,
        build / "Template-Toolkit-3.106.tar.gz",
        max_bytes=4 * 1024 * 1024,
    )
    image = context.build_staged_image(build, build / "Dockerfile", label="bugzilla")

    port = free_port()
    _, service_group = service_identity()
    socket_gid = grp.getgrnam(service_group).gr_gid
    compose = context.compose(
        HERE / "compose.yml",
        {
            "BUGZILLA_IMAGE": image,
            "BUGZILLA_ROOT": os.fspath(bugzilla_root),
            "BZ_URLBASE": f"http://127.0.0.1:{port}/",
            "FCGI_RUN": os.fspath(fcgi_run),
            "VAPACHE_SOCKET_GID": str(socket_gid),
        },
        local_images=(image,),
    )
    # Setup temporarily makes the staged tree root-owned so the unprivileged
    # FastCGI process cannot rewrite executable CGI. Restore ownership before
    # the harness removes its scenario directory, including on failed runs.
    context.add_cleanup(
        lambda: compose.run_once(
            "bugzilla",
            ["-R", f"{os.getuid()}:{os.getgid()}", os.fspath(bugzilla_root)],
            entrypoint="/usr/bin/chown",
            user="0",
            check=False,
        )
    )
    compose.pull()
    compose.up()

    socket_path = fcgi_run / "fcgi.sock"
    if not socket_path.is_socket():
        raise DeploymentError("Bugzilla FastCGI runner did not create its Unix socket")
    socket_meta = socket_path.stat()
    if (
        socket_meta.st_uid != 33
        or socket_meta.st_gid != socket_gid
        or stat.S_IMODE(socket_meta.st_mode) != 0o660
    ):
        raise DeploymentError(
            "Bugzilla FastCGI socket has unsafe ownership/mode: "
            f"uid={socket_meta.st_uid} gid={socket_meta.st_gid} "
            f"mode={stat.S_IMODE(socket_meta.st_mode):04o}"
        )
    trusted_owners = " ".join(str(owner) for owner in sorted({0, os.getuid()}))
    common = f"""
DirectoryIndex index.cgi
ProxyPassMatch ^/(.*\\.cgi(/.*)?)$ "unix:{socket_path}|fcgi://localhost{bugzilla_root}/"
<Directory "{bugzilla_root}">
    Options FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
<FilesMatch "(\\.pm|\\.pl|\\.tmpl|^localconfig.*)$">
    Require all denied
</FilesMatch>
"""
    vapache_extra = (
        f"VapacheFastCGIStablePath On unix:{socket_path} 33 33 {trusted_owners}\n"
        + common
    )
    config, pid_file = common_vapache_config(
        context.run_dir,
        port,
        bugzilla_root,
        capabilities=("FastCgi",),
        extra=vapache_extra,
    )
    server = start_vapache(context, config, pid_file, port)
    require_response(port, "/", contains=b"Bugzilla")
    require_response(port, "/Bugzilla.pm", status=403)
    require_response(port, "/localconfig", status=403)
    require_response(port, "/rest.cgi/version", contains=b'"version"')

    opener: urllib.request.OpenerDirector | None = None
    if variant["session"] == "authenticated":
        opener = login(port)

    if variant["workflow"] == "query":
        if opener is None:
            require_response(port, "/query.cgi", contains=b"Search")
        else:
            opener_contains(opener, f"http://127.0.0.1:{port}/query.cgi", b"Search")
    elif opener is None:
        require_response(port, "/editparams.cgi", contains=b"Log in")
    else:
        opener_contains(
            opener,
            f"http://127.0.0.1:{port}/editparams.cgi",
            b"Required Settings",
        )

    if variant["reload"] == "after-login":
        server.reload()
        if opener is None:
            require_response(port, "/", contains=b"Bugzilla")
        else:
            opener_contains(opener, f"http://127.0.0.1:{port}/", b"Log&nbsp;out")

    if context.benchmark:
        apache_port = free_port()
        apache_config = common_apache_config(
            context.run_dir,
            apache_port,
            bugzilla_root,
            modules=(
                "mpm_event",
                "authz_core",
                "authz_host",
                "dir",
                "proxy",
                "proxy_fcgi",
            ),
            extra=common,
        )
        start_apache(context, apache_config, apache_port)
        require_response(apache_port, "/", contains=b"Bugzilla")
        differential_benchmark(
            port,
            apache_port,
            "/index.cgi",
            context.artifact_dir / "apache-vapache-benchmark.json",
        )
