---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-MASTODON-001
scenario: mastodon-proxy
---

# Put Mastodon web and streaming services behind Vapache

This tutorial publishes Mastodon at `https://social.example.test/`. Vapache
sends the streaming route to Mastodon's streaming service and all other
requests to the web service.

## What you will do

You will configure Mastodon's public domain, bind its web and streaming
services to loopback, order the Vapache routes, publish one status, reload
Vapache, reconnect the user stream, and receive the status event.

## Before you start

You need a Linux VPS with Vapache and a working Mastodon installation with
PostgreSQL, Redis, the web service, the streaming service, and background jobs.
You also need a certificate for `social.example.test` and a Mastodon test
account.

## 1. Configure Mastodon's public authority

Set these values in the production environment:

```text
LOCAL_DOMAIN=social.example.test
WEB_DOMAIN=social.example.test
```

Bind the web service to `127.0.0.1:3000` and the streaming service to
`127.0.0.1:4000`. Keep the existing database, Redis, secrets, and media
settings unchanged. Keep the worker count selected for the host's available
memory and CPU.

Restart the Mastodon services and verify both private listeners before you
change Vapache.

## 2. Configure Vapache

The streaming route must appear before the catch-all web route:

```apache
<VirtualHost *:443>
    ServerName social.example.test
    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/social.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/social.example.test/privkey.pem

    ProxyPreserveHost On
    ProxyPass /api/v1/streaming http://127.0.0.1:4000/api/v1/streaming
    ProxyPassReverse /api/v1/streaming http://127.0.0.1:4000/api/v1/streaming
    ProxyPass / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/
</VirtualHost>
```

## 3. Test the web and streaming paths

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ curl --fail https://social.example.test/api/v2/instance
```

Sign in with the test account and open its user stream. Reload Vapache and
confirm that the streaming client reconnects. Publish a status through the web
application and confirm that the same status arrives on the reconnected stream.
This tests the web service, background job, Redis delivery, streaming service,
and WebSocket route together.

Delete the test status when the check succeeds.

## Roll back

Restore the previous Vapache routes and Mastodon domain settings. Restart the
Mastodon services and reload Vapache. Keep the production secrets and database
unchanged.

<!--
Deployment contract only; not operator instructions.
--scenario mastodon-proxy
Canonical dimensions: `workers=two`, `stream=user`, `reload=before-publish`.
Scenario storage budget: 4096 MiB.
[Scenario](../../tests/deployments/scenarios/mastodon-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/mastodon-proxy/driver.py)
-->
