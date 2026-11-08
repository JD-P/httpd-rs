---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-WAGTAIL-001
scenario: wagtail-proxy
---

# Run the tested Wagtail and Gunicorn deployment

This tutorial runs the Wagtail Bakery Demo through Gunicorn and Vapache. The
canonical case uses two Gunicorn workers and verifies an authenticated Wagtail
admin session across reload.

## What you will do

You will run the canonical `wagtail-proxy` deployment, read the Wagtail API,
complete a CSRF-bound admin login, reload Vapache, and reuse the authenticated
session.

## Before you start

You need Docker, 3072 MiB for the scenario, the Docker safety reserve, and root
or passwordless `sudo`. The harness downloads a digest-verified Bakery Demo
source revision and builds it from locked Python requirements.

## 1. Build and run the deployment

```console
$ cargo build --locked --release -p vapached
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario wagtail-proxy \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `workers=two`, `workflow=admin`, and
`reload=after-login`.

## 2. Verify the result

The final status must be `passed`. The workflow opens the Bakery home page,
checks fixture content through the page API, completes an admin login with its
CSRF token and cookie, opens the page administration view, reloads Vapache, and
opens the dashboard with the existing session.

## 3. Inspect the tested configuration

```console
$ find deployment-results -path '*wagtail-proxy-*' -name vapache.conf -print
```

The configuration uses `ProxyPreserveHost On` because Django validates the
public authority. The private container address is not an accepted application
host. Only the media directory is writable.

## 4. Adapt the pattern

Configure Django `ALLOWED_HOSTS`, CSRF trusted origins, and the public scheme for
the Vapache authority. Preserve `Host` only after Vapache validates it. Keep the
application image immutable and mount a separate media directory.

## Clean up

The harness removes Wagtail, PostgreSQL, the staged image, volumes, and private
network. It retains the tested configuration and workflow evidence.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/wagtail-proxy/scenario.toml)
and [driver](../../tests/deployments/scenarios/wagtail-proxy/driver.py).
