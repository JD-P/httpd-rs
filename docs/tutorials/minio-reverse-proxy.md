---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-MINIO-001
scenario: minio-proxy
---

# Put MinIO behind httpd-rs on a VPS

This tutorial installs MinIO and publishes it at
`https://s3.example.test/`. MinIO verifies signatures against the public host,
so httpd-rs preserves the validated `Host` field.

## What you will do

You will install MinIO and its client, create a systemd service, bind MinIO to
loopback, configure httpd-rs, upload an object with a signed S3 request, reload
httpd-rs, download the object, and remove the test data.

## Before you start

Complete [Prepare a Debian VPS for a httpd-rs
tutorial](prepare-debian-vps.md). Point `s3.example.test` at the VPS and open
TCP ports 80 and 443 in the provider firewall.

## 1. Install verified MinIO and `mc` releases

```console
$ sudo apt install golang-go git
$ curl --fail --show-error --location \
    'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x4405F3F0DDBA1B9E68A31D2512C74390F9AAC728' \
    --output /tmp/minio-signing-key.asc
$ test "$(gpg --show-keys --with-colons /tmp/minio-signing-key.asc \
    | awk -F: '$1 == "fpr" { print $10; exit }')" \
    = 4405F3F0DDBA1B9E68A31D2512C74390F9AAC728
$ gpg --batch --import /tmp/minio-signing-key.asc
$ git clone --filter=blob:none --no-checkout \
    https://github.com/minio/minio.git /tmp/minio-source
$ git -C /tmp/minio-source fetch --depth=1 origin \
    tag RELEASE.2025-09-07T16-13-09Z
$ git -C /tmp/minio-source verify-tag RELEASE.2025-09-07T16-13-09Z
$ git -C /tmp/minio-source checkout --detach \
    07c3a429bfed433e49018cb0f78a52145d4bedeb
$ test "$(git -C /tmp/minio-source rev-parse HEAD)" \
    = 07c3a429bfed433e49018cb0f78a52145d4bedeb
$ git clone --filter=blob:none --no-checkout \
    https://github.com/minio/mc.git /tmp/mc-source
$ git -C /tmp/mc-source fetch --depth=1 origin \
    tag RELEASE.2025-08-13T08-35-41Z
$ git -C /tmp/mc-source verify-tag RELEASE.2025-08-13T08-35-41Z
$ git -C /tmp/mc-source checkout --detach \
    7394ce0dd2a80935aded936b09fa12cbb3cb8096
$ test "$(git -C /tmp/mc-source rev-parse HEAD)" \
    = 7394ce0dd2a80935aded936b09fa12cbb3cb8096
$ cd /tmp/minio-source && go build -trimpath -o /tmp/minio .
$ cd /tmp/mc-source && go build -trimpath -o /tmp/mc .
$ sudo install -m 0755 /tmp/minio /usr/local/bin/minio
$ sudo install -m 0755 /tmp/mc /usr/local/bin/mc
```

The pinned signing-key fingerprint and commit IDs make both source checkouts
reviewable. Go verifies downloaded modules against each checkout's `go.sum`.

## 2. Create the MinIO service

```console
$ sudo adduser --system --group --home /var/lib/minio minio
$ sudo install -d -o minio -g minio -m 0750 /srv/minio/data
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

Create a limited account for the public test. These `read` commands do not put
either password in shell history:

```console
$ read -rsp 'MinIO root password: ' MINIO_ROOT_PASSWORD; echo
$ read -rsp 'New test-account password: ' MINIO_TEST_PASSWORD; echo
$ mc alias set minio-local http://127.0.0.1:9000 \
    minio-admin "$MINIO_ROOT_PASSWORD"
$ mc admin user add minio-local httpd-rs-test "$MINIO_TEST_PASSWORD"
$ mc admin policy attach minio-local readwrite --user httpd-rs-test
$ unset MINIO_ROOT_PASSWORD
```

Keep `MINIO_TEST_PASSWORD` in this shell until the final test finishes.

## 3. Configure httpd-rs

Create `/etc/apache2/sites-available/minio.conf` with a temporary HTTP-only
host, enable it, and obtain the certificate:

```apache
<VirtualHost *:80>
    ServerName s3.example.test
</VirtualHost>
```

```console
$ sudo a2ensite minio.conf
$ sudo httpd-rsctl configtest
$ sudo systemctl reload httpd-rs.service
$ sudo certbot certonly --apache --domain s3.example.test
```

Replace it with the final configuration:

```apache
<VirtualHost *:80>
    ServerName s3.example.test
    Redirect permanent / https://s3.example.test/
</VirtualHost>

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

Test the configuration, reload httpd-rs, and verify renewal:

```console
$ sudo httpd-rsctl configtest
$ sudo systemctl reload httpd-rs.service
$ sudo certbot renew --dry-run
```

## 4. Test signed object operations

Use the limited test account and the password retained in the shell:

```console
$ mc alias set httpd-rs-test https://s3.example.test \
    httpd-rs-test "$MINIO_TEST_PASSWORD"
$ mc mb httpd-rs-test/httpd-rs-check
$ dd if=/dev/urandom of=/tmp/httpd-rs-minio.bin bs=1M count=2
$ mc cp /tmp/httpd-rs-minio.bin httpd-rs-test/httpd-rs-check/object.bin
$ sudo systemctl reload httpd-rs.service
$ mc cp httpd-rs-test/httpd-rs-check/object.bin /tmp/httpd-rs-minio-check.bin
$ cmp /tmp/httpd-rs-minio.bin /tmp/httpd-rs-minio-check.bin
$ mc ls httpd-rs-test/httpd-rs-check
```

These operations test signed request identity, streamed bodies, response
streaming, and listing. Remove the object and bucket after `cmp` succeeds:

```console
$ mc rm httpd-rs-test/httpd-rs-check/object.bin
$ mc rb httpd-rs-test/httpd-rs-check
$ mc admin user remove minio-local httpd-rs-test
$ mc alias remove httpd-rs-test
$ mc alias remove minio-local
$ unset MINIO_TEST_PASSWORD
```

<!--
Deployment contract only; not operator instructions.
--scenario minio-proxy
Documentation case: `payload=streaming`, `operation=listing`, `reload=before-read`.
Scenario storage budget: 1024 MiB.
[Scenario](../../tests/deployments/scenarios/minio-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/minio-proxy/driver.py)
-->
