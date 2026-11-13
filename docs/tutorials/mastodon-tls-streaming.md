---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-MASTODON-001
scenario: mastodon-proxy
---

# Put Mastodon web and streaming services behind httpd-rs

This tutorial publishes Mastodon at `https://social.example.test/`. httpd-rs
sends the streaming route to Mastodon's streaming service and all other
requests to the web service.

## What you will do

You will install Mastodon, PostgreSQL, Redis, Ruby, and Node.js, run Mastodon's
production setup, bind its web and streaming services to loopback, configure
httpd-rs, publish one status, reload httpd-rs, reconnect the user stream, and
receive the status event.

## Before you start

Complete [Prepare a Debian VPS for a httpd-rs
tutorial](prepare-debian-vps.md). Use a VPS with at least 4 GiB of memory and
point `social.example.test` at it. Open TCP ports 80 and 443 in the provider
firewall.

## 1. Install Mastodon's system dependencies

```console
$ sudo apt install autoconf bison build-essential curl ffmpeg file g++ gcc git \
    gnupg imagemagick libffi-dev libgdbm-dev libicu-dev libidn-dev libjemalloc-dev \
    libncurses-dev libpq-dev libprotobuf-dev libreadline-dev libssl-dev \
    libxml2-dev libxslt1-dev libyaml-dev pkg-config postgresql \
    postgresql-contrib protobuf-compiler redis-server ruby-dev ruby-full zlib1g-dev
$ curl --fail --show-error --location \
    https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    --output /tmp/nodesource.asc
$ gpg --show-keys --with-colons /tmp/nodesource.asc | \
    awk -F: '$1 == "fpr" { print $10; exit }' | \
    grep -Fx 6F71F525282841EEDAF851B42F59B5F99B1BE0B4
$ sudo install -d -m 0755 /etc/apt/keyrings
$ gpg --dearmor --output /tmp/nodesource.gpg /tmp/nodesource.asc
$ sudo install -o root -g root -m 0644 /tmp/nodesource.gpg \
    /etc/apt/keyrings/nodesource.gpg
$ printf '%s\n' \
    'Types: deb' \
    'URIs: https://deb.nodesource.com/node_22.x' \
    'Suites: nodistro' \
    'Components: main' \
    'Signed-By: /etc/apt/keyrings/nodesource.gpg' | \
    sudo tee /etc/apt/sources.list.d/nodesource.sources >/dev/null
$ sudo apt update
$ sudo apt install nodejs
$ sudo corepack enable
$ sudo gem install bundler --no-document
$ sudo adduser --disabled-login --gecos '' mastodon
```

## 2. Install Mastodon and run its setup

The commit below is the exact source for Mastodon v4.7.5.

```console
$ sudo -iu mastodon git clone https://github.com/mastodon/mastodon.git live
$ sudo -iu mastodon git -C /home/mastodon/live checkout \
    24cd1c875a1ac393e587421726394d5692ff5496
$ sudo -iu mastodon bash -lc \
    'test "$(git -C ~/live rev-parse HEAD)" = 24cd1c875a1ac393e587421726394d5692ff5496'
$ sudo -iu mastodon bash -lc \
    'cd ~/live && bundle config deployment true && bundle config without development test'
$ sudo -iu mastodon bash -lc 'cd ~/live && bundle install -j2'
$ sudo -iu mastodon bash -lc 'cd ~/live && yarn install --immutable'
$ sudo -iu mastodon bash -lc \
    'cd ~/live && RAILS_ENV=production bundle exec rake mastodon:setup'
```

When setup asks for the domain, enter `social.example.test`. Accept the local
PostgreSQL and Redis defaults, enter the production mail settings, and create
the administrator account used in the final test. Setup writes the generated
secrets to `/home/mastodon/live/.env.production`.

Install the upstream systemd units:

```console
$ sudo cp /home/mastodon/live/dist/mastodon-web.service \
    /home/mastodon/live/dist/mastodon-sidekiq.service \
    /home/mastodon/live/dist/mastodon-streaming.service \
    /etc/systemd/system/
$ sudo install -d /etc/systemd/system/mastodon-web.service.d \
    /etc/systemd/system/mastodon-streaming.service.d
```

Create `/etc/systemd/system/mastodon-web.service.d/listen.conf`:

```systemd
[Service]
Environment=BIND=127.0.0.1
Environment=PORT=3000
```

Create `/etc/systemd/system/mastodon-streaming.service.d/listen.conf`:

```systemd
[Service]
Environment=BIND=127.0.0.1
Environment=PORT=4000
```

Start the three services and verify their private health endpoints:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now mastodon-web mastodon-sidekiq mastodon-streaming
$ curl --fail http://127.0.0.1:3000/health
$ curl --fail http://127.0.0.1:4000/api/v1/streaming/health
```

## 3. Confirm Mastodon's public domain

Confirm that `/home/mastodon/live/.env.production` contains this value:

```text
LOCAL_DOMAIN=social.example.test
```

This tutorial uses the same domain for account names and the web interface, so
it does not need a separate `WEB_DOMAIN` value.

## 4. Configure httpd-rs

Create `/etc/apache2/sites-available/mastodon.conf` with a temporary HTTP-only
host, enable it, and obtain the certificate:

```apache
<VirtualHost *:80>
    ServerName social.example.test
</VirtualHost>
```

```console
$ sudo a2ensite mastodon.conf
$ sudo httpd-rsctl configtest
$ sudo systemctl reload httpd-rs.service
$ sudo certbot certonly --apache --domain social.example.test
```

Replace it with the final configuration. The streaming route must appear
before the catch-all web route:

```apache
<VirtualHost *:80>
    ServerName social.example.test
    Redirect permanent / https://social.example.test/
</VirtualHost>

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

Test the configuration, reload httpd-rs, and verify renewal:

```console
$ sudo httpd-rsctl configtest
$ sudo systemctl reload httpd-rs.service
$ sudo certbot renew --dry-run
```

## 5. Test the web and streaming paths

```console
$ curl --fail https://social.example.test/api/v2/instance
```

Sign in with the test account and open its user stream. Reload httpd-rs and
confirm that the streaming client reconnects. Publish a status through the web
application and confirm that the same status arrives on the reconnected stream.
This tests the web service, background job, Redis delivery, streaming service,
and WebSocket route together.

Delete the test status when the check succeeds.

<!--
Deployment contract only; not operator instructions.
--scenario mastodon-proxy
Documentation case: `workers=one`, `stream=user`, `reload=before-publish`.
Scenario storage budget: 4096 MiB.
[Scenario](../../tests/deployments/scenarios/mastodon-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/mastodon-proxy/driver.py)
-->
