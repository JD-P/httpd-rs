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

You will install Mastodon, PostgreSQL, Redis, Ruby, and Node.js, run Mastodon's
production setup, bind its web and streaming services to loopback, configure
Vapache, publish one status, reload Vapache, reconnect the user stream, and
receive the status event.

## Before you start

Complete [Prepare a Debian VPS for a Vapache
tutorial](prepare-debian-vps.md). Use a VPS with at least 4 GiB of memory and
point `social.example.test` at it. Open TCP ports 80 and 443 in the provider
firewall.

## 1. Install Mastodon's system dependencies

```console
$ sudo apt install autoconf bison build-essential curl ffmpeg file g++ gcc git \
    imagemagick libffi-dev libgdbm-dev libicu-dev libidn-dev libjemalloc-dev \
    libncurses-dev libpq-dev libprotobuf-dev libreadline-dev libssl-dev \
    libxml2-dev libxslt1-dev libyaml-dev pkg-config postgresql \
    postgresql-contrib protobuf-compiler redis-server ruby-dev ruby-full zlib1g-dev
$ curl --fail --show-error --location https://deb.nodesource.com/setup_22.x \
    --output /tmp/nodesource-setup.sh
$ sudo bash /tmp/nodesource-setup.sh
$ sudo apt install nodejs
$ sudo corepack enable
$ sudo gem install bundler --no-document
$ sudo adduser --disabled-login --gecos '' mastodon
```

## 2. Install Mastodon and run its setup

```console
$ sudo -iu mastodon git clone https://github.com/mastodon/mastodon.git live
$ sudo -iu mastodon git -C /home/mastodon/live checkout v4.7.5
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
$ sudo certbot certonly --standalone --domain social.example.test
```

## 3. Confirm Mastodon's public domain

Confirm that `/home/mastodon/live/.env.production` contains this value:

```text
LOCAL_DOMAIN=social.example.test
```

This tutorial uses the same domain for account names and the web interface, so
it does not need a separate `WEB_DOMAIN` value.

## 4. Configure Vapache

Create `/etc/apache2/sites-available/mastodon.conf`. The streaming route must
appear before the catch-all web route:

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

Enable the virtual host, test the configuration, and start Vapache:

```console
$ sudo a2ensite mastodon.conf
$ sudo vapachectl configtest
$ sudo systemctl enable --now vapache.service
```

## 5. Test the web and streaming paths

```console
$ curl --fail https://social.example.test/api/v2/instance
```

Sign in with the test account and open its user stream. Reload Vapache and
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
