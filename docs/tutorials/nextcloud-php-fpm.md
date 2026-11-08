---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-NEXTCLOUD-001
scenario: nextcloud-fpm
---

# Run the tested Nextcloud and PHP-FPM deployment

This tutorial runs Nextcloud through PHP-FPM and sends WebDAV methods and a
large request body through Vapache. The application code and configuration are
immutable; the data directory remains writable.

## What you will do

You will run the canonical `nextcloud-fpm` deployment, upload a large object,
inspect it with `PROPFIND`, move it, reload Vapache, download the exact bytes,
and delete it.

## Before you start

You need Docker, 3072 MiB for the scenario, the Docker safety reserve, and root
or passwordless `sudo`.

## 1. Build and run the deployment

```console
$ cargo build --locked --release -p vapached
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario nextcloud-fpm \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `upload=large`, `dav=move`, and
`reload=before-download`.

## 2. Verify the result

The final status must be `passed`. The workflow checks installation status,
creates a collection, uploads a large object, performs `PROPFIND` and `MOVE`,
reloads Vapache, checks the exact download length and bytes, and deletes the
object.

## 3. Inspect the tested configuration

```console
$ find deployment-results -path '*nextcloud-fpm-*' -name vapache.conf -print
```

The configuration enables `FastCgi`, registers the PHP-FPM Unix socket, and
uses `CGIPassAuth On` in the Nextcloud directory so the WebDAV front controller
receives HTTP authentication. It denies direct access to `config`, `data`,
`lib`, dot files, and command-line entry points.

## 4. Adapt the pattern

Keep Nextcloud code and `config.php` immutable to PHP-FPM. Leave only the data
tree writable. Preserve the `Authorization` field only in the directory that
needs it. Test the WebDAV methods and body sizes used by real clients.

## Clean up

The workflow deletes its WebDAV object. The harness removes Nextcloud, MariaDB,
their volumes, and their private network. It retains the configuration and
result evidence.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/nextcloud-fpm/scenario.toml)
and [driver](../../tests/deployments/scenarios/nextcloud-fpm/driver.py).
