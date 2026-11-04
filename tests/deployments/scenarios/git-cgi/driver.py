"""Exercise two production Git CGI applications: Gitweb and smart HTTP."""

from __future__ import annotations

import os
import shutil
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
    make_readable_tree,
    require_response,
    start_apache,
    start_vapache,
)


GIT = Path("/usr/bin/git") if Path("/usr/bin/git").exists() else Path(shutil.which("git") or "git")


def make_repository(root: Path) -> Path:
    working = root / "working"
    projects = root / "projects"
    working.mkdir()
    projects.mkdir()
    command([GIT, "init", "--initial-branch=main"], cwd=working)
    (working / "README.md").write_text("git-cgi-deployment-marker\n")
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Vapache Integration",
            "GIT_AUTHOR_EMAIL": "integration@vapache.invalid",
            "GIT_COMMITTER_NAME": "Vapache Integration",
            "GIT_COMMITTER_EMAIL": "integration@vapache.invalid",
        }
    )
    command([GIT, "add", "README.md"], cwd=working, env=environment)
    command([GIT, "commit", "-m", "deployment fixture"], cwd=working, env=environment)
    bare = projects / "demo.git"
    command([GIT, "clone", "--bare", os.fspath(working), os.fspath(bare)])
    command([GIT, "--git-dir", os.fspath(bare), "update-server-info"])
    make_readable_tree(projects)
    return projects


def locate_git_apps() -> tuple[Path, Path, Path]:
    module = command(["perl", "-MCGI", "-e", "1"], check=False)
    if module.returncode != 0:
        raise DeploymentError("Gitweb requires Perl CGI.pm (install libcgi-pm-perl)")
    gitweb = Path("/usr/share/gitweb/gitweb.cgi")
    gitweb_static = Path("/usr/share/gitweb/static")
    package_backend = Path("/usr/lib/git-core/git-http-backend")
    exec_path = Path(command([GIT, "--exec-path"]).stdout.strip())
    backend = package_backend if package_backend.exists() else exec_path / "git-http-backend"
    missing = [path for path in (gitweb, gitweb_static, backend) if not path.exists()]
    if missing:
        raise DeploymentError("missing Git CGI application files: " + ", ".join(map(str, missing)))
    return gitweb, gitweb_static, backend


def run(context: CaseContext, variant: dict[str, str]) -> None:
    versions = command([GIT, "--version"]).stdout
    package_versions = command(
        ["dpkg-query", "-W", "-f=${Package} ${Version}\\n", "git", "gitweb", "libcgi-pm-perl"],
        check=False,
    )
    (context.artifact_dir / "git-version.txt").write_text(versions + (package_versions.stdout or ""))
    projects = make_repository(context.run_dir)
    gitweb, gitweb_static, backend = locate_git_apps()
    gitweb_config = context.run_dir / "gitweb_config.perl"
    gitweb_config.write_text(
        f"$projectroot = '{projects}';\n"
        "$site_name = 'Vapache Gitweb Integration';\n"
        "$projects_list = $projectroot;\n"
        "$feature{'pathinfo'}{'default'} = [1];\n"
        "@stylesheets = ('/gitweb-static/gitweb.css');\n"
        "1;\n"
    )
    os.chmod(gitweb_config, 0o644)
    auth_file = context.run_dir / "htpasswd"
    auth_file.write_text("alice:{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=\n")
    os.chmod(auth_file, 0o644)
    empty_docroot = context.run_dir / "empty"
    empty_docroot.mkdir()
    port = free_port()

    authorization = ""
    if variant["access"] == "basic":
        authorization = f"""
<LocationMatch "^/(gitweb|git)(/|$)">
    AuthType Basic
    AuthName "Git deployment"
    AuthUserFile "{auth_file}"
    Require valid-user
</LocationMatch>
"""
    extra = f"""
SetEnv GITWEB_CONFIG "{gitweb_config}"
SetEnv GIT_PROJECT_ROOT "{projects}"
SetEnv GIT_HTTP_EXPORT_ALL 1
ScriptAlias /gitweb "{gitweb}"
ScriptAlias /git/ "{backend}/"
Alias /gitweb-static/ "{gitweb_static}/"
<Directory "{gitweb.parent}">
    Options ExecCGI FollowSymLinks
    Require all granted
</Directory>
<Directory "{backend.parent}">
    Options ExecCGI FollowSymLinks
    Require all granted
</Directory>
<Directory "{gitweb_static}">
    Options FollowSymLinks
    Require all granted
</Directory>
{authorization}
"""
    config, pid_file = common_vapache_config(
        context.run_dir,
        port,
        empty_docroot,
        capabilities=("Cgi",),
        extra=extra,
    )
    server = start_vapache(context, config, pid_file, port)
    request_headers: dict[str, str] = {}
    if variant["access"] == "basic":
        require_response(port, "/gitweb", status=401)
        require_response(port, "/git/demo.git/info/refs?service=git-upload-pack", status=401)
        request_headers["Authorization"] = basic_authorization("alice", "secret")

    require_response(port, "/gitweb", contains=b"Vapache Gitweb Integration", headers=request_headers)
    require_response(port, "/gitweb/?p=demo.git;a=summary", contains=b"demo.git", headers=request_headers)
    info_headers, info_body = require_response(
        port,
        "/git/demo.git/info/refs?service=git-upload-pack",
        headers=request_headers,
    )
    if "application/x-git-upload-pack-advertisement" not in info_headers.get("content-type", ""):
        raise DeploymentError(f"unexpected smart-HTTP content type: {info_headers}")
    if b"git-upload-pack" not in info_body:
        raise DeploymentError("smart-HTTP advertisement was missing git-upload-pack")

    clone = context.run_dir / "clone"
    clone_command = [os.fspath(GIT)]
    if request_headers:
        clone_command.extend(["-c", f"http.extraHeader=Authorization: {request_headers['Authorization']}"])
    clone_command.extend(["clone", f"http://127.0.0.1:{port}/git/demo.git", os.fspath(clone)])
    command(clone_command, timeout=60)
    if (clone / "README.md").read_text() != "git-cgi-deployment-marker\n":
        raise DeploymentError("smart-HTTP clone did not reproduce the repository")

    if variant["reload"] == "after-start":
        server.reload()
        require_response(port, "/gitweb", contains=b"Vapache Gitweb Integration", headers=request_headers)
    if context.benchmark:
        path = "/gitweb/?p=demo.git;a=summary" if variant["application"] == "gitweb" else "/git/demo.git/info/refs?service=git-upload-pack"
        apache_port = free_port()
        apache_extra = f"""
ScriptSock "{context.run_dir / 'apache-cgid.sock'}"
SetEnv GITWEB_CONFIG "{gitweb_config}"
SetEnv GIT_PROJECT_ROOT "{projects}"
SetEnv GIT_HTTP_EXPORT_ALL 1
ScriptAlias /gitweb "{gitweb}"
ScriptAlias /git/ "{backend}/"
Alias /gitweb-static/ "{gitweb_static}/"
<Directory "{gitweb.parent}">
    Options ExecCGI FollowSymLinks
    Require all granted
</Directory>
<Directory "{backend.parent}">
    Options ExecCGI FollowSymLinks
    Require all granted
</Directory>
<Directory "{gitweb_static}">
    Options FollowSymLinks
    Require all granted
</Directory>
{authorization}
"""
        apache_config = common_apache_config(
            context.run_dir,
            apache_port,
            empty_docroot,
            modules=(
                "mpm_event",
                "authz_core",
                "authz_host",
                "auth_basic",
                "authn_file",
                "alias",
                "cgid",
                "env",
                "mime",
            ),
            extra=apache_extra,
        )
        start_apache(context, apache_config, apache_port)
        require_response(apache_port, path, headers=request_headers)
        benchmark_headers = (
            (f"Authorization: {request_headers['Authorization']}",) if request_headers else ()
        )
        differential_benchmark(
            port,
            apache_port,
            path,
            context.artifact_dir / "apache-vapache-benchmark.json",
            headers=benchmark_headers,
        )

