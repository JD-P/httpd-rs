---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-GITEA-001
scenario: gitea-proxy
---

# Put Gitea behind Vapache on a VPS

This tutorial publishes an existing Gitea service below `/gitea/` at
`https://git.example.test/gitea/`.

## What you will do

You will bind Gitea to loopback, set its public URL, add the Vapache proxy
route, create a repository, push a commit, reload Vapache, and clone it.

## Before you start

You need a Linux VPS with Vapache, Gitea, Git, and a certificate for
`git.example.test`. Gitea must already run as a systemd service. Keep the Gitea
data directory and database backup procedure unchanged.

## 1. Configure Gitea's public URL

Set these values in Gitea's `app.ini`:

```ini
[server]
DOMAIN = git.example.test
ROOT_URL = https://git.example.test/gitea/
HTTP_ADDR = 127.0.0.1
HTTP_PORT = 3000
```

Restart Gitea and confirm that the private endpoint responds:

```console
$ sudo systemctl restart gitea.service
$ curl --fail http://127.0.0.1:3000/api/v1/version
```

## 2. Configure Vapache

Add the route to the TLS virtual host. The trailing slashes are significant:

```apache
<VirtualHost *:443>
    ServerName git.example.test
    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/git.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/git.example.test/privkey.pem

    ProxyPass /gitea/ http://127.0.0.1:3000/
    ProxyPassReverse /gitea/ http://127.0.0.1:3000/
</VirtualHost>
```

## 3. Test the public route

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ curl --fail https://git.example.test/gitea/api/v1/version
```

Follow one login redirect and confirm that it remains below `/gitea/` and does
not expose port `3000`.

## 4. Test Git smart HTTP

Create a repository through the Gitea interface. Then run:

```console
$ git clone https://git.example.test/gitea/alice/example.git /tmp/gitea-example
$ cd /tmp/gitea-example
$ printf '%s\n' 'Vapache Gitea test' > vapache-test.txt
$ git add vapache-test.txt
$ git commit -m 'Test Gitea through Vapache'
$ git push
$ sudo systemctl reload vapache.service
$ git clone https://git.example.test/gitea/alice/example.git /tmp/gitea-check
```

Confirm that `/tmp/gitea-check/vapache-test.txt` contains the expected text.
Remove `/tmp/gitea-example` and `/tmp/gitea-check` after the test succeeds.

<!--
Deployment contract only; not operator instructions.
--scenario gitea-proxy
Canonical dimensions: `mount=subpath`, `reload=before-transfer`, `benchmark=repository`.
Scenario storage budget: 1536 MiB.
[Scenario](../../tests/deployments/scenarios/gitea-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/gitea-proxy/driver.py)
-->
