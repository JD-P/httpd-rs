---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-WORDPRESS-001
scenario: wordpress-fpm
---

# Run the tested WordPress and PHP-FPM deployment

This tutorial installs WordPress behind Vapache and PHP-FPM. The canonical case
uses pretty permalinks, a disk cache for static assets, an immutable PHP release
tree, a writable upload directory, and a graceful reload.

## What you will do

You will run the canonical `wordpress-fpm` deployment, verify a real WordPress
workflow, inspect the stable FastCGI path policy, and identify which directories
can be writable.

## Before you start

You need Docker, 2048 MiB for the scenario, the Docker safety reserve, and root
or passwordless `sudo`. The scenario pulls digest-pinned WordPress and MariaDB
images.

## 1. Build and run the deployment

```console
$ cargo build --locked --release -p vapached
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario wordpress-fpm \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `permalinks=pretty`, `asset_cache=disk`, and
`reload=after-start`.

## 2. Verify the result

The final status must be `passed`. The workflow installs WordPress, uploads and
retrieves a PNG, opens a pretty permalink, reads the REST API, checks that PHP
source is not exposed, denies PHP in the upload tree, confirms a static cache
hit, reloads Vapache, and reads the REST root again.

## 3. Inspect the tested configuration

```console
$ find deployment-results -path '*wordpress-fpm-*' -name vapache.conf -print
```

The configuration enables `AccessFiles` and `FastCgi`. It registers an exact
Unix socket with `VapacheFastCGIStablePath`. The release tree is immutable to
PHP-FPM. Only `wp-content/uploads` is writable, and a `FilesMatch` rule denies
PHP execution in that directory.

## 4. Adapt the pattern

Give PHP-FPM a protected Unix socket. Keep every PHP file and ancestor directory
outside the backend's mutation authority. Put media in a separate writable
tree. Perform core, plugin, and theme updates by creating and activating a new
immutable release instead of editing the live tree from the dashboard.

## Clean up

The harness removes WordPress, MariaDB, their network, volumes, and selected
images. It retains the tested Vapache configuration and workflow evidence.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/wordpress-fpm/scenario.toml)
and [driver](../../tests/deployments/scenarios/wordpress-fpm/driver.py).
