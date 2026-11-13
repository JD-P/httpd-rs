---
doc_type: project
audience: documentation-contributor
status: normative
---

# Build and host the documentation site

The documentation site is a static MkDocs Material build. The checked source
is under `docs/`, and the hostable output is written to `site/`.

## Build locally

Create an isolated Python environment and install the pinned site toolchain:

```console
$ python3 -m venv .venv-docs
$ . .venv-docs/bin/activate
$ python3 -m pip install --requirement docs/requirements.txt
```

Build httpd-rs, run the executable documentation contracts, and render the
site in strict mode:

```console
$ cargo build --locked -p httpd-rs
$ python3 tests/docs.py
$ mkdocs build --strict
```

Host the resulting `site/` directory with any static-file service. To inspect
changes locally instead, run:

```console
$ mkdocs serve
```

The preview is available at `http://127.0.0.1:8000/` by default.

## Deploy with GitHub Pages

The `docs-pages.yml` workflow validates and builds the site for documentation
pull requests. A push to `main`, or a manual workflow dispatch, also publishes
the build through GitHub Pages.

The first deployment may require selecting **GitHub Actions** as the Pages
source under the repository's **Settings → Pages** screen. The workflow uses
the repository's Pages environment and does not need a deployment secret.

For the default project Pages address, the published URL is:

```text
https://jd-p.github.io/httpd-rs/
```

If the repository moves or receives a custom domain, update `site_url` in
`mkdocs.yml` before publishing.
