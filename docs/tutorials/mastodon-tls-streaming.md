---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-MASTODON-001
scenario: mastodon-proxy
---

# Run the tested Mastodon TLS and streaming deployment

This tutorial runs Mastodon web, streaming, background-job, PostgreSQL, and
Redis services behind one Vapache TLS virtual host. It routes the streaming
prefix before the general web route.

## What you will do

You will run the canonical `mastodon-proxy` deployment, authenticate to the API,
open a user stream, reload Vapache, publish a status, receive the exact event
through WebSocket, and remove the status.

## Before you start

You need Docker, OpenSSL, 4096 MiB for the scenario, the Docker safety reserve,
and root or passwordless `sudo`. The complete cold run can take 20 minutes.

## 1. Build and run the deployment

```console
$ cargo build --locked --release -p vapached
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario mastodon-proxy \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `workers=two`, `stream=user`, and
`reload=before-publish`.

## 2. Verify the result

The final status must be `passed`. The workflow checks TLS health and instance
identity, verifies bearer credentials, opens an authenticated stream, reloads
and reconnects, creates a status through Puma, waits for Sidekiq and Redis to
deliver the same status through the streaming service, reads it, and deletes it.

## 3. Inspect the tested configuration

```console
$ find deployment-results -path '*mastodon-proxy-*' -name vapache.conf -print
```

The TLS connection state supplies the public HTTPS scheme. The configuration
preserves the validated public `Host`, routes `/api/v1/streaming` to the
streaming service before routing `/` to the web service, and reconnects the
stream after a configuration-generation change.

## 4. Adapt the pattern

Replace every fixture secret and test certificate. Keep Rails encryption, OTP,
VAPID, database, and object-storage secrets stable across upgrades. Make the
Mastodon local domain equal the public Vapache authority. Do not accept a
client-supplied forwarded scheme on a plaintext listener.

## Clean up

The workflow deletes the created status. The harness removes all Mastodon
services, state volumes, media staging, and the private network. It retains the
configuration and event-delivery evidence.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/mastodon-proxy/scenario.toml)
and [driver](../../tests/deployments/scenarios/mastodon-proxy/driver.py).
