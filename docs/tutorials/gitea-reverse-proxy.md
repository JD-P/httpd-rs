---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-GITEA-001
scenario: gitea-proxy
---

# Put Gitea behind Vapache on a VPS

This tutorial installs Gitea and publishes it below `/gitea/` at
`https://git.example.test/gitea/`.

## What you will do

You will install Gitea with SQLite, create its systemd service, bind it to
loopback, add the Vapache proxy route, create a repository, push a commit,
reload Vapache, and clone it.

## Before you start

Complete [Prepare a Debian VPS for a Vapache
tutorial](prepare-debian-vps.md). Point `git.example.test` at the VPS and open
TCP ports 80 and 443 in the provider firewall.

## 1. Install Gitea

```console
$ sudo apt install git
$ curl --fail --show-error --location \
    --output /tmp/gitea \
    https://dl.gitea.com/gitea/1.26.0/gitea-1.26.0-linux-amd64
$ sudo install -m 0755 /tmp/gitea /usr/local/bin/gitea
$ sudo adduser --system --group --home /var/lib/gitea git
$ sudo install -d -o git -g git -m 0750 /var/lib/gitea/data \
    /var/lib/gitea/log /var/lib/gitea/custom
$ sudo install -d -o root -g git -m 0750 /etc/gitea
$ sudo certbot certonly --standalone --domain git.example.test
```

Create `/etc/gitea/app.ini`:

```ini
APP_NAME = Gitea
RUN_USER = git
WORK_PATH = /var/lib/gitea

[database]
DB_TYPE = sqlite3
PATH = /var/lib/gitea/data/gitea.db

[repository]
ROOT = /var/lib/gitea/data/gitea-repositories

[server]
DOMAIN = git.example.test
ROOT_URL = https://git.example.test/gitea/
HTTP_ADDR = 127.0.0.1
HTTP_PORT = 3000

[log]
ROOT_PATH = /var/lib/gitea/log
```

Let the first-run installer update the configuration, then create
`/etc/systemd/system/gitea.service`:

```console
$ sudo chown git:git /etc/gitea/app.ini
$ sudo chmod 0600 /etc/gitea/app.ini
```

```systemd
[Unit]
Description=Gitea
After=network.target

[Service]
User=git
Group=git
WorkingDirectory=/var/lib/gitea
ExecStart=/usr/local/bin/gitea web --config /etc/gitea/app.ini
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Start Gitea and confirm that the private endpoint responds:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now gitea.service
$ curl -I http://127.0.0.1:3000/gitea/
```

## 2. Configure Vapache

Create `/etc/apache2/sites-available/gitea.conf`. The trailing slashes are
significant:

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

Enable the virtual host, test the configuration, and start Vapache:

```console
$ sudo a2ensite gitea.conf
$ sudo vapachectl configtest
$ sudo systemctl enable --now vapache.service
```

## 3. Complete the Gitea installation

Open `https://git.example.test/gitea/`. Keep SQLite and the repository paths
from step 1, create the administrator account, and complete the installer.
After the installer succeeds, prevent the Gitea process from rewriting its
configuration and check the public API:

```console
$ sudo chown root:git /etc/gitea/app.ini
$ sudo chmod 0640 /etc/gitea/app.ini
$ sudo systemctl restart gitea.service
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
Documentation case: `mount=subpath`, `reload=before-transfer`, `benchmark=repository`.
Scenario storage budget: 1536 MiB.
[Scenario](../../tests/deployments/scenarios/gitea-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/gitea-proxy/driver.py)
-->
