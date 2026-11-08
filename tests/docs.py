#!/usr/bin/env python3
"""Validate user documentation and execute its Vapache behavior contracts."""

from __future__ import annotations

import grp
import http.client
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
CONTRACTS = DOCS / "contracts.toml"
USER_DOC_ROOTS = (
    DOCS / "tutorials",
    DOCS / "how-to",
    DOCS / "reference",
    DOCS / "explanation",
)
PROJECT_DOCS = (
    DOCS / "README.md",
    DOCS / "audiences.md",
    DOCS / "style.md",
    DOCS / "audits" / "apache-2.4.md",
)
ALLOWED_TYPES = {
    "landing",
    "tutorial",
    "how-to",
    "reference",
    "explanation",
    "project",
}
ALLOWED_PROSE_STYLES = {"controlled", "discursive"}
FORBIDDEN_USER_WORDS = ("easy", "obvious", "obviously", "just", "simply")
TESTED_EXAMPLE = re.compile(
    r"<!-- tested-example: ([^\s]+) -->\s*\n"
    r"```apache\n(.*?)\n```",
    re.DOTALL,
)
MARKDOWN_LINK = re.compile(r"\[[^]]+\]\(([^)]+)\)")


class DocsError(RuntimeError):
    pass


def markdown_files() -> list[Path]:
    files = list(PROJECT_DOCS)
    for directory in USER_DOC_ROOTS:
        files.extend(sorted(directory.rglob("*.md")))
    return files


def metadata(path: Path, text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        raise DocsError(f"{path.relative_to(ROOT)}: missing metadata header")
    try:
        header, _ = text[4:].split("\n---\n", 1)
    except ValueError as error:
        raise DocsError(f"{path.relative_to(ROOT)}: unterminated metadata header") from error
    result: dict[str, str] = {}
    for line in header.splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            raise DocsError(f"{path.relative_to(ROOT)}: invalid metadata line {line!r}")
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip()
    doc_type = result.get("doc_type")
    if doc_type not in ALLOWED_TYPES:
        raise DocsError(f"{path.relative_to(ROOT)}: invalid doc_type {doc_type!r}")
    if not result.get("audience"):
        raise DocsError(f"{path.relative_to(ROOT)}: missing audience metadata")
    prose_style = result.get("prose_style", "controlled")
    if prose_style not in ALLOWED_PROSE_STYLES:
        raise DocsError(f"{path.relative_to(ROOT)}: invalid prose_style {prose_style!r}")
    if prose_style == "discursive" and (
        doc_type != "explanation" or "contributor" not in result["audience"]
    ):
        raise DocsError(
            f"{path.relative_to(ROOT)}: discursive prose is limited to contributor explanation"
        )
    if (
        doc_type == "explanation"
        and "contributor" in result["audience"]
        and prose_style != "discursive"
    ):
        raise DocsError(
            f"{path.relative_to(ROOT)}: contributor explanation must use discursive prose"
        )
    return result


def prose_without_code(text: str) -> str:
    return re.sub(r"```.*?```", "", text, flags=re.DOTALL)


def is_user_doc(path: Path) -> bool:
    return any(path.is_relative_to(directory) for directory in USER_DOC_ROOTS)


def check_style_and_structure() -> None:
    for path in markdown_files():
        if not path.is_file():
            raise DocsError(f"missing documentation page: {path.relative_to(ROOT)}")
        text = path.read_text(encoding="utf-8")
        data = metadata(path, text)
        if is_user_doc(path) and data.get("prose_style", "controlled") == "controlled":
            prose = prose_without_code(text)
            for word in FORBIDDEN_USER_WORDS:
                if re.search(rf"\b{re.escape(word)}\b", prose, re.IGNORECASE):
                    raise DocsError(
                        f"{path.relative_to(ROOT)}: controlled-language word is not allowed: {word}"
                    )
        if data["doc_type"] == "tutorial":
            for heading in ("## What you will do", "## Before you start"):
                if heading not in text:
                    raise DocsError(f"{path.relative_to(ROOT)}: tutorial is missing {heading!r}")
            if data.get("scenario") and path.name != "migrate-debian-static-site.md":
                if not re.search(r"^## 1\. Install", text, re.MULTILINE):
                    raise DocsError(
                        f"{path.relative_to(ROOT)}: deployment tutorial must start with installation"
                    )
                has_shared_setup = "(prepare-debian-vps.md)" in text
                has_inline_setup = "sudo apt install /tmp/vapache.deb" in text
                if not has_shared_setup and not has_inline_setup:
                    raise DocsError(
                        f"{path.relative_to(ROOT)}: deployment tutorial omits the fresh-VPS setup"
                    )
                for phrase in ("already installed", "must already run", "working installation"):
                    if phrase in text.lower():
                        raise DocsError(
                            f"{path.relative_to(ROOT)}: deployment tutorial starts after setup: "
                            f"{phrase!r}"
                        )
        if data["doc_type"] == "how-to" and "## Prerequisites" not in text:
            raise DocsError(f"{path.relative_to(ROOT)}: how-to is missing prerequisites")


def check_deployment_tutorial_security() -> None:
    tutorials = DOCS / "tutorials"
    for path in sorted(tutorials.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        data = metadata(path, text)
        if "certbot certonly --standalone" in text:
            raise DocsError(
                f"{path.relative_to(ROOT)}: deployment tutorials must not use standalone Certbot"
            )
        if "nodesource-setup" in text or "setup_22.x" in text:
            raise DocsError(
                f"{path.relative_to(ROOT)}: downloaded repository setup scripts are not allowed"
            )
        if data.get("scenario") and "SSLEngine On" in text:
            for required in (
                "certbot certonly --apache --domain",
                "<VirtualHost *:80>",
                "Redirect permanent / https://",
                "certbot renew --dry-run",
            ):
                if required not in text:
                    raise DocsError(
                        f"{path.relative_to(ROOT)}: TLS tutorial is missing {required!r}"
                    )

    shared = (tutorials / "prepare-debian-vps.md").read_text(encoding="utf-8")
    for required in (
        "SHA256SUMS",
        "sha256sum --check --strict",
        "python3-certbot-apache",
        "a2dissite 000-default.conf",
        "vapache-switch --yes",
    ):
        if required not in shared:
            raise DocsError(f"shared VPS setup is missing {required!r}")

    git_cgi = (tutorials / "git-cgi.md").read_text(encoding="utf-8")
    if "htpasswd -B -C 12" not in git_cgi:
        raise DocsError("Git CGI tutorial must use bcrypt password hashes")
    if "http://git.example.test" in git_cgi:
        raise DocsError("Git CGI tutorial must not send Basic authentication over HTTP")

    wordpress = (tutorials / "wordpress-php-fpm.md").read_text(encoding="utf-8")
    if "--allow-root" in wordpress:
        raise DocsError("WordPress tutorial must not run WP-CLI as root")
    for required in (
        "adduser --system --group --home /var/lib/wordpress-deploy",
        "sudo -u wordpress-deploy wp",
        "sudo chown -R root:root /srv/wordpress/current",
        "user = www-data",
    ):
        if required not in wordpress:
            raise DocsError(f"WordPress privilege boundary is missing {required!r}")

    verified_artifacts = {
        "gitea-reverse-proxy.md": (
            "7C9E68152594688862D62AF62D9AE806EC1592E2",
            "gpg --batch --verify /tmp/gitea.asc /tmp/gitea",
        ),
        "grafana-reverse-proxy.md": (
            "B53AE77BADB630A683046005963FA27710458545",
            "signed-by=/etc/apt/keyrings/grafana.gpg",
        ),
        "jenkins-reverse-proxy.md": (
            "63667EE74BBA1F0A08A698725BA31D57EF5975CA",
            "signed-by=/usr/share/keyrings/jenkins-keyring.asc",
        ),
        "mastodon-tls-streaming.md": (
            "6F71F525282841EEDAF851B42F59B5F99B1BE0B4",
            "Signed-By: /etc/apt/keyrings/nodesource.gpg",
        ),
        "minio-reverse-proxy.md": (
            "4405F3F0DDBA1B9E68A31D2512C74390F9AAC728",
            "git -C /tmp/minio-source verify-tag",
            "git -C /tmp/mc-source verify-tag",
        ),
        "nextcloud-php-fpm.md": (
            "5810b06e75678384973d8d86387ee39f4c086d79dfa92f15fcb743aaba36eaa9",
            "sha256sum --check --strict",
        ),
        "wordpress-php-fpm.md": (
            "63AF7AA15067C05616FDDD88A3A2E8F226F0BC06",
            "gpg --batch --verify /tmp/wp-cli.phar.asc /tmp/wp-cli.phar",
        ),
    }
    for name, required_values in verified_artifacts.items():
        text = (tutorials / name).read_text(encoding="utf-8")
        for required in required_values:
            if required not in text:
                raise DocsError(f"docs/tutorials/{name}: download verification lost {required!r}")


def check_safe_rust_claim() -> None:
    source_files = sorted((ROOT / "crates" / "server" / "src").glob("*.rs"))
    source_lines = 0
    unsafe_sites = 0
    for path in source_files:
        lines = path.read_text(encoding="utf-8").splitlines()
        source_lines += len(lines)
        unsafe_sites += sum(
            1
            for line in lines
            if re.search(r"\bunsafe\b", line) and not line.lstrip().startswith("//")
        )
    if not source_lines or unsafe_sites / source_lines >= 0.01:
        raise DocsError(
            "the documented more-than-99%-safe-Rust claim no longer matches "
            f"the source inventory ({unsafe_sites} unsafe sites across {source_lines} lines)"
        )
    claim = "More than 99% of the Vapache server source is safe Rust"
    for relative in (
        "explanation/security-expectations.md",
        "how-to/evaluate-security-driven-migration.md",
    ):
        path = DOCS / relative
        if claim not in path.read_text(encoding="utf-8"):
            raise DocsError(f"{path.relative_to(ROOT)}: safe-Rust claim is missing")


def check_links() -> None:
    for path in markdown_files():
        text = path.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(text):
            target = match.group(1).strip()
            if target.startswith(("https://", "http://", "mailto:", "#")):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError as error:
                raise DocsError(
                    f"{path.relative_to(ROOT)}: local link escapes the repository: {target}"
                ) from error
            if not resolved.exists():
                raise DocsError(f"{path.relative_to(ROOT)}: broken local link: {target}")


def local_link_targets(path: Path, text: str) -> set[Path]:
    targets: set[Path] = set()
    for match in MARKDOWN_LINK.finditer(text):
        target = match.group(1).strip().split("#", 1)[0]
        if not target or target.startswith(("https://", "http://", "mailto:")):
            continue
        targets.add((path.parent / target).resolve())
    return targets


def check_how_to_catalog() -> None:
    directory = DOCS / "how-to"
    catalog = directory / "README.md"
    text = catalog.read_text(encoding="utf-8")
    pages = {path.name for path in directory.glob("*.md") if path != catalog}
    catalog_pages = set(re.findall(r"\]\(([^/)]+\.md)\)", text))
    if catalog_pages != pages:
        raise DocsError(
            "how-to catalog is stale: "
            f"missing={sorted(pages - catalog_pages)}, "
            f"extra={sorted(catalog_pages - pages)}"
        )


def check_explanation_catalog() -> None:
    directory = DOCS / "explanation"
    catalog = directory / "README.md"
    text = catalog.read_text(encoding="utf-8")
    pages = {path.name for path in directory.glob("*.md") if path != catalog}
    catalog_pages = set(re.findall(r"\]\(([^/)]+\.md)\)", text))
    if catalog_pages != pages:
        raise DocsError(
            "explanation catalog is stale: "
            f"missing={sorted(pages - catalog_pages)}, "
            f"extra={sorted(catalog_pages - pages)}"
        )


def check_tested_examples() -> set[str]:
    seen: set[str] = set()
    for path in markdown_files():
        text = path.read_text(encoding="utf-8")
        for match in TESTED_EXAMPLE.finditer(text):
            relative, embedded = match.groups()
            example = DOCS / "examples" / relative
            if not example.is_file():
                raise DocsError(f"{path.relative_to(ROOT)}: missing tested example {relative}")
            canonical = example.read_text(encoding="utf-8").rstrip("\n")
            if embedded.rstrip("\n") != canonical:
                raise DocsError(
                    f"{path.relative_to(ROOT)}: embedded example differs from docs/examples/{relative}"
                )
            seen.add(example.relative_to(ROOT).as_posix())
    return seen


def load_contracts() -> list[dict]:
    data = tomllib.loads(CONTRACTS.read_text(encoding="utf-8"))
    if data.get("schema") != 1:
        raise DocsError("docs/contracts.toml: unsupported schema")
    contracts = data.get("contract", [])
    ids = [contract.get("id") for contract in contracts]
    if len(ids) != len(set(ids)):
        raise DocsError("docs/contracts.toml: contract IDs must be unique")
    return contracts


def check_contract_inventory(contracts: list[dict], embedded_examples: set[str]) -> None:
    deployment_scenarios: set[str] = set()
    deployment_documents = {
        contract.get("scenario", ""): (ROOT / contract["document"]).resolve()
        for contract in contracts
        if contract.get("kind") == "deployment"
    }
    for contract in contracts:
        contract_id = contract.get("id", "")
        if not re.fullmatch(r"DOC-[A-Z]+(?:-[A-Z]+)*-\d{3}", contract_id):
            raise DocsError(f"invalid documentation contract ID: {contract_id!r}")
        document = ROOT / contract["document"]
        if not document.is_file():
            raise DocsError(f"{contract_id}: document is missing")
        if contract_id not in document.read_text(encoding="utf-8"):
            raise DocsError(f"{contract_id}: ID is not present in {contract['document']}")
        if contract["kind"] == "deployment":
            scenario = contract.get("scenario", "")
            manifest = ROOT / "tests" / "deployments" / "scenarios" / scenario / "scenario.toml"
            driver = manifest.parent / "driver.py"
            if not manifest.is_file() or not driver.is_file():
                raise DocsError(f"{contract_id}: deployment scenario is missing: {scenario}")
            page = document.read_text(encoding="utf-8")
            page_metadata = metadata(document, page)
            if page_metadata.get("scenario") != scenario:
                raise DocsError(f"{contract_id}: tutorial scenario metadata does not match {scenario}")
            if f"--scenario {scenario}" not in page:
                raise DocsError(f"{contract_id}: tutorial does not run its scenario")
            manifest_data = tomllib.loads(manifest.read_text(encoding="utf-8"))
            for name, value in manifest_data["documentation"].items():
                if f"`{name}={value}`" not in page:
                    raise DocsError(
                        f"{contract_id}: tutorial omits documentation dimension {name}={value}"
                    )
            if str(manifest_data["disk_mb"]) not in page:
                raise DocsError(f"{contract_id}: tutorial omits its scenario storage budget")
            catalog = DOCS / "tutorials" / "README.md"
            row = next(
                (line for line in catalog.read_text(encoding="utf-8").splitlines()
                 if f"]({document.name})" in line),
                None,
            )
            if row is None:
                raise DocsError(f"{contract_id}: tutorial is missing from the catalog")
            for mode in manifest_data.get("modes", []):
                if f"`{mode}`" not in row:
                    raise DocsError(f"{contract_id}: catalog omits mode {mode}")
            columns = [column.strip() for column in row.strip().strip("|").split("|")]
            if len(columns) != 4 or not columns[3]:
                raise DocsError(f"{contract_id}: catalog needs a similar-software entry")
            deployment_scenarios.add(scenario)
            continue

        if contract["kind"] == "evidence":
            page = document.read_text(encoding="utf-8")
            if metadata(document, page).get("doc_type") != "how-to":
                raise DocsError(f"{contract_id}: evidence binding must name a how-to")
            targets = local_link_targets(document, page)
            evidence_paths = contract.get("evidence_paths", [])
            scenarios = contract.get("scenarios", [])
            if not evidence_paths and not scenarios:
                raise DocsError(f"{contract_id}: evidence binding is empty")
            for relative in evidence_paths:
                evidence_path = (ROOT / relative).resolve()
                if not evidence_path.is_file():
                    raise DocsError(f"{contract_id}: evidence path is missing: {relative}")
                if evidence_path not in targets:
                    raise DocsError(
                        f"{contract_id}: how-to does not link its evidence path: {relative}"
                    )
            marker_paths: set[str] = set()
            for binding in contract.get("evidence_markers", []):
                if "::" not in binding:
                    raise DocsError(f"{contract_id}: invalid evidence marker: {binding}")
                relative, marker = binding.split("::", 1)
                if relative not in evidence_paths:
                    raise DocsError(
                        f"{contract_id}: marker path is not declared as evidence: {relative}"
                    )
                marker_paths.add(relative)
                source = (ROOT / relative).read_text(encoding="utf-8")
                if marker not in source:
                    raise DocsError(
                        f"{contract_id}: evidence marker is missing from {relative}: {marker}"
                    )
            if marker_paths != set(evidence_paths):
                raise DocsError(
                    f"{contract_id}: every evidence path needs a stable marker: "
                    f"missing={sorted(set(evidence_paths) - marker_paths)}"
                )
            for scenario in scenarios:
                manifest = (
                    ROOT / "tests" / "deployments" / "scenarios" / scenario / "scenario.toml"
                )
                if not manifest.is_file() or scenario not in deployment_documents:
                    raise DocsError(
                        f"{contract_id}: scenario lacks a deployment contract: {scenario}"
                    )
                if deployment_documents[scenario] not in targets:
                    raise DocsError(
                        f"{contract_id}: how-to does not link its scenario tutorial: {scenario}"
                    )
            continue

        example = ROOT / contract["example"]
        if not example.is_file():
            raise DocsError(f"{contract_id}: example is missing")
        relative_example = example.relative_to(ROOT).as_posix()
        if relative_example not in embedded_examples:
            raise DocsError(f"{contract_id}: {relative_example} is not embedded in a checked page")
        apache_test = contract.get("apache_test")
        if apache_test:
            test_path, test_name = apache_test.split(":", 1)
            source = (ROOT / test_path).read_text(encoding="utf-8")
            function = test_name.rsplit(".", 1)[-1]
            if f"def {function}(" not in source:
                raise DocsError(f"{contract_id}: Apache differential test is missing: {apache_test}")

    manifests = ROOT / "tests" / "deployments" / "scenarios"
    implemented_scenarios = {
        tomllib.loads(path.read_text(encoding="utf-8"))["id"]
        for path in manifests.glob("*/scenario.toml")
    }
    if deployment_scenarios != implemented_scenarios:
        raise DocsError(
            "deployment tutorial inventory is stale: "
            f"missing={sorted(implemented_scenarios - deployment_scenarios)}, "
            f"extra={sorted(deployment_scenarios - implemented_scenarios)}"
        )
    workflow = (
        ROOT / ".github" / "workflows" / "application-integration.yml"
    ).read_text(encoding="utf-8")
    if 'cron: "17 5 * * 0"' not in workflow or "profile=canonical" not in workflow:
        raise DocsError("deployment scenarios require a scheduled canonical application workflow")
    if 'cron: "31 5 * * 3"' not in workflow or "profile=documentation" not in workflow:
        raise DocsError("deployment tutorials require a scheduled documentation workflow")


def check_reference_evidence() -> list[str]:
    config_source = (ROOT / "crates" / "server" / "src" / "config.rs").read_text(
        encoding="utf-8"
    )
    try:
        capability_impl = config_source.split("impl Capability {", 1)[1].split(
            "pub(crate) fn parse", 1
        )[0]
    except IndexError as error:
        raise DocsError("could not locate the authoritative Capability name table") from error
    implemented = set(re.findall(r'Self::\w+\s*=>\s*"([A-Za-z0-9]+)"', capability_impl))
    reference = (DOCS / "reference" / "apache-compatibility.md").read_text(encoding="utf-8")
    try:
        capability_section = reference.split("## Default-off capabilities", 1)[1].split(
            "\n## ", 1
        )[0]
    except IndexError as error:
        raise DocsError("could not locate the default-off capability reference") from error
    documented = set(re.findall(r"\| `([A-Za-z0-9]+)` \|", capability_section))
    if documented != implemented:
        raise DocsError(
            "default-off capability reference is stale: "
            f"missing={sorted(implemented - documented)}, extra={sorted(documented - implemented)}"
        )

    conformance = (ROOT / "tests" / "conformance.py").read_text(encoding="utf-8")
    for path in markdown_files():
        text = path.read_text(encoding="utf-8")
        for test_name in re.findall(r"Conformance\.(test_[a-z0-9_]+)", text):
            if f"def {test_name}(" not in conformance:
                raise DocsError(f"{path.relative_to(ROOT)}: missing evidence case {test_name}")
    return sorted(documented)


def vapached_binary() -> Path:
    configured = os.environ.get("VAPACHED")
    candidates = [Path(configured)] if configured else []
    candidates.extend(
        (
            ROOT / "target" / "debug" / "vapached",
            ROOT / "target" / "release" / "vapached",
        )
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    raise DocsError("missing vapached; run cargo build -p vapached or set VAPACHED")


def service_identity() -> tuple[str, str]:
    return pwd.getpwuid(os.geteuid()).pw_name, grp.getgrgid(os.getegid()).gr_name


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def base_config(root: Path, listener: str, extra: str) -> str:
    user, group = service_identity()
    return f'''ServerRoot "{root}"
Listen {listener}
User {user}
Group {group}
PidFile "{root / 'vapached.pid'}"
ErrorLog "{root / 'error.log'}"
LogLevel warn
ServerName docs-default.invalid
TypesConfig "{root / 'mime.types'}"
<Directory />
    AllowOverride None
    Require all denied
</Directory>
{extra.rstrip()}
'''


def run_command(command: list[str], *, timeout: float = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def write_config(root: Path, text: str) -> Path:
    types = root / "mime.types"
    types.write_text("text/html html\n", encoding="utf-8")
    os.chmod(types, 0o644)
    path = root / "vapache.conf"
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o644)
    return path


def test_config_contract(binary: Path, contract: dict) -> None:
    source = (ROOT / contract["example"]).read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="vapache-doc-config-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o755)
        cgi_root = root / "cgi-bin"
        cgi_root.mkdir(mode=0o755)
        source = source.replace("/srv/www/example/cgi-bin/", f"{cgi_root}/")
        config = write_config(root, base_config(root, "127.0.0.1:0", source))
        if contract["kind"] == "capability-audit":
            audit = run_command([str(binary), "-f", str(config), "--audit-capabilities"])
            combined = audit.stdout + audit.stderr
            if audit.returncode != 0 or contract["output"] not in combined:
                raise DocsError(
                    f"{contract['id']}: capability audit failed\nstdout:\n{audit.stdout}\nstderr:\n{audit.stderr}"
                )
            normal = run_command([str(binary), "-f", str(config), "-t"])
            if normal.returncode == 0 or contract["output"] not in normal.stderr:
                raise DocsError(f"{contract['id']}: normal mode did not require the audited capability")
        elif contract["kind"] == "config-reject":
            result = run_command([str(binary), "-f", str(config), "-t"])
            combined = result.stdout + result.stderr
            if result.returncode == 0 or contract["error"] not in combined:
                raise DocsError(
                    f"{contract['id']}: expected fail-closed rejection\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
                )
        else:
            raise DocsError(f"{contract['id']}: unsupported configuration contract kind")


def test_documented_capability_names(binary: Path, capabilities: list[str]) -> None:
    declarations = "".join(f"VapacheCapability {name} On\n" for name in capabilities)
    with tempfile.TemporaryDirectory(prefix="vapache-doc-capabilities-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o755)
        config = write_config(root, base_config(root, "127.0.0.1:0", declarations))
        result = run_command([str(binary), "-f", str(config), "-t", "--strict-config"])
        if result.returncode != 0 or "Syntax OK" not in result.stdout:
            raise DocsError(
                "documented capability names are not accepted by vapached\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )


def request(port: int, method: str, path: str) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        body = b"test" if method == "POST" else None
        connection.request(
            method,
            path,
            body=body,
            headers={"Host": "www.example.test", "Connection": "close"},
        )
        response = connection.getresponse()
        payload = response.read()
        headers = {name.lower(): value for name, value in response.getheaders()}
        return response.status, headers, payload
    finally:
        connection.close()


def wait_for_server(process: subprocess.Popen[bytes], port: int, log: Path) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
            raise DocsError(f"vapached exited during documentation test:\n{output}")
        try:
            request(port, "GET", "/")
            return
        except (OSError, http.client.HTTPException):
            time.sleep(0.05)
    output = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    raise DocsError(f"timed out waiting for documentation server:\n{output}")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def test_runtime_contract(binary: Path, contract: dict) -> None:
    example = (ROOT / contract["example"]).read_text(encoding="utf-8")
    example_root = (ROOT / contract["example"]).parent
    with tempfile.TemporaryDirectory(prefix="vapache-doc-runtime-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o755)
        document_root = root / "www"
        document_root.mkdir(mode=0o755)
        for name in ("index.html", "404.html"):
            shutil.copyfile(example_root / name, document_root / name)
            os.chmod(document_root / name, 0o644)
        port = available_port()
        virtual_host = example.replace(
            "/srv/www/example/releases/2026-11-07/public", str(document_root)
        ).replace("<VirtualHost *:80>", f"<VirtualHost 127.0.0.1:{port}>")
        config = write_config(root, base_config(root, f"127.0.0.1:{port}", virtual_host))
        checked = run_command([str(binary), "-f", str(config), "-t", "--strict-config"])
        if checked.returncode != 0 or "Syntax OK" not in checked.stdout:
            raise DocsError(
                f"{contract['id']}: documented configuration failed validation\n"
                f"stdout:\n{checked.stdout}\nstderr:\n{checked.stderr}"
            )
        log = root / "foreground.log"
        with log.open("wb") as output:
            process = subprocess.Popen(
                [str(binary), "-f", str(config), "-DFOREGROUND"],
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                wait_for_server(process, port, log)
                for expected in contract.get("request", []):
                    status, headers, body = request(port, expected["method"], expected["path"])
                    if status != expected["status"]:
                        raise DocsError(
                            f"{contract['id']}: {expected['method']} {expected['path']} "
                            f"returned {status}, expected {expected['status']}"
                        )
                    if "body" in expected and body != expected["body"].encode():
                        raise DocsError(
                            f"{contract['id']}: {expected['method']} {expected['path']} "
                            f"returned body {body!r}, expected {expected['body'].encode()!r}"
                        )
                    if "header" in expected and expected["header"].lower() not in headers:
                        raise DocsError(
                            f"{contract['id']}: {expected['method']} {expected['path']} "
                            f"did not return {expected['header']}"
                        )
            finally:
                stop_process(process)


def execute_contracts(contracts: list[dict], capabilities: list[str]) -> None:
    binary = vapached_binary()
    test_documented_capability_names(binary, capabilities)
    for contract in contracts:
        if contract["kind"] in {"deployment", "evidence"}:
            continue
        if contract["kind"] == "runtime":
            test_runtime_contract(binary, contract)
        else:
            test_config_contract(binary, contract)


def main() -> int:
    try:
        check_style_and_structure()
        check_deployment_tutorial_security()
        check_safe_rust_claim()
        check_links()
        check_how_to_catalog()
        check_explanation_catalog()
        embedded_examples = check_tested_examples()
        contracts = load_contracts()
        check_contract_inventory(contracts, embedded_examples)
        capabilities = check_reference_evidence()
        execute_contracts(contracts, capabilities)
    except (DocsError, OSError, subprocess.SubprocessError) as error:
        print(f"documentation test failed: {error}", file=sys.stderr)
        return 1
    local = sum(contract["kind"] not in {"deployment", "evidence"} for contract in contracts)
    evidence = sum(contract["kind"] == "evidence" for contract in contracts)
    scheduled = sum(contract["kind"] == "deployment" for contract in contracts)
    print(
        "documentation test passed: "
        f"{local} local executable contracts, {evidence} how-to evidence bindings, "
        f"{scheduled} scheduled deployment bindings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
