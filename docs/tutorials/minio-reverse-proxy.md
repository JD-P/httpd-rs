---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-MINIO-001
scenario: minio-proxy
---

# Put MinIO behind Vapache on a VPS

This tutorial installs MinIO and publishes it at
`https://s3.example.test/`. MinIO verifies signatures against the public host,
so Vapache preserves the validated `Host` field.

## What you will do

You will install MinIO and its client, create a systemd service, bind MinIO to
loopback, configure Vapache, upload an object with a signed S3 request, reload
Vapache, download the object, and remove the test data.

## Before you start

Complete [Prepare a Debian VPS for a Vapache
tutorial](prepare-debian-vps.md). Point `s3.example.test` at the VPS and open
TCP ports 80 and 443 in the provider firewall.

## 1. Install MinIO and create its service

```console
$ curl --fail --show-error --location \
    --output /tmp/minio https://dl.min.io/server/minio/release/linux-amd64/minio
$ curl --fail --show-error --location \
    --output /tmp/mc https://dl.min.io/client/mc/release/linux-amd64/mc
$ sudo install -m 0755 /tmp/minio /usr/local/bin/minio
$ sudo install -m 0755 /tmp/mc /usr/local/bin/mc
$ sudo adduser --system --group --home /var/lib/minio minio
$ sudo install -d -o minio -g minio -m 0750 /srv/minio/data
$ sudo certbot certonly --standalone --domain s3.example.test
```

Create `/etc/default/minio` and replace both example credentials with new
values:

```text
MINIO_ROOT_USER=minio-admin
MINIO_ROOT_PASSWORD=replace-this-with-a-long-random-password
MINIO_SERVER_URL=https://s3.example.test
MINIO_VOLUMES=/srv/minio/data
MINIO_OPTS=--address 127.0.0.1:9000 --console-address 127.0.0.1:9001
```

Protect the file:

```console
$ sudo chown root:minio /etc/default/minio
$ sudo chmod 0640 /etc/default/minio
```

Create `/etc/systemd/system/minio.service`:

```systemd
[Unit]
Description=MinIO object storage
After=network-online.target
Wants=network-online.target

[Service]
User=minio
Group=minio
EnvironmentFile=/etc/default/minio
ExecStart=/usr/local/bin/minio server $MINIO_OPTS $MINIO_VOLUMES
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Start MinIO and test its private health endpoint:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now minio.service
$ curl --fail http://127.0.0.1:9000/minio/health/live
```

## 2. Configure Vapache

Create `/etc/apache2/sites-available/minio.conf`:

```apache
<VirtualHost *:443>
    ServerName s3.example.test
    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/s3.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/s3.example.test/privkey.pem

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:9000/
    ProxyPassReverse / http://127.0.0.1:9000/
</VirtualHost>
```

Enable the virtual host, test the configuration, and start Vapache:

```console
$ sudo a2ensite minio.conf
$ sudo vapachectl configtest
$ sudo systemctl enable --now vapache.service
```

## 3. Test signed object operations

Replace `ACCESS_KEY` and `SECRET_KEY` with the `MINIO_ROOT_USER` and
`MINIO_ROOT_PASSWORD` values that you set in step 1, then run:

```console
$ mc alias set vapache-test https://s3.example.test ACCESS_KEY SECRET_KEY
$ mc mb vapache-test/vapache-check
$ dd if=/dev/urandom of=/tmp/vapache-minio.bin bs=1M count=2
$ mc cp /tmp/vapache-minio.bin vapache-test/vapache-check/object.bin
$ sudo systemctl reload vapache.service
$ mc cp vapache-test/vapache-check/object.bin /tmp/vapache-minio-check.bin
$ cmp /tmp/vapache-minio.bin /tmp/vapache-minio-check.bin
$ mc ls vapache-test/vapache-check
```

These operations test signed request identity, streamed bodies, response
streaming, and listing. Remove the object and bucket after `cmp` succeeds:

```console
$ mc rm vapache-test/vapache-check/object.bin
$ mc rb vapache-test/vapache-check
```

<!--
Deployment contract only; not operator instructions.
--scenario minio-proxy
Documentation case: `payload=streaming`, `operation=listing`, `reload=before-read`.
Scenario storage budget: 1024 MiB.
[Scenario](../../tests/deployments/scenarios/minio-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/minio-proxy/driver.py)
-->
