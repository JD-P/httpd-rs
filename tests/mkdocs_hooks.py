"""MkDocs transformations that preserve repository documentation contracts."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
MARKDOWN_LINK = re.compile(r"(\[[^]]+\]\()([^)]+)(\))")


def on_page_markdown(markdown: str, page, config, files) -> str:  # noqa: ANN001
    """Point links outside docs at the corresponding source file on GitHub.

    The checked Markdown deliberately uses repository-relative links because
    tests/docs.py binds operator documentation to executable evidence. Those
    links would escape a static documentation site, so only the rendered form
    is rewritten.
    """

    source = DOCS / page.file.src_uri
    repository = config["repo_url"].rstrip("/")

    def rewrite(match: re.Match[str]) -> str:
        destination = match.group(2)
        if destination.startswith(("#", "/", "http://", "https://", "mailto:")):
            return match.group(0)
        path_text, marker, fragment = destination.partition("#")
        candidate = (source.parent / unquote(path_text)).resolve()
        try:
            candidate.relative_to(DOCS)
            return match.group(0)
        except ValueError:
            pass
        try:
            relative = candidate.relative_to(ROOT).as_posix()
        except ValueError:
            return match.group(0)
        rendered = f"{repository}/blob/main/{relative}"
        if marker:
            rendered += f"#{fragment}"
        return f"{match.group(1)}{rendered}{match.group(3)}"

    return MARKDOWN_LINK.sub(rewrite, markdown)
