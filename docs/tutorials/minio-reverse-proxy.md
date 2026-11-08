---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-MINIO-001
scenario: minio-proxy
---

# Put MinIO behind Vapache on a VPS

This tutorial publishes an existing MinIO service at
`https://s3.example.test/`. MinIO verifies signatures against the public host,
so Vapache preserves the validated `Host` field.

## What you will do

You will bind MinIO to loopback, set its public URL, configure Vapache, upload
an object with a signed S3 request, reload Vapache, download the object, and
remove the test data.

## Before you start

You need a Linux VPS with Vapache, MinIO, the MinIO client `mc`, and a
certificate for `s3.example.test`. MinIO must already have its persistent data
directory and systemd service.

## 1. Configure MinIO

Set the public URL in the environment file used by the MinIO service:

```text
MINIO_SERVER_URL=https://s3.example.test
```

Add `--address 127.0.0.1:9000` to the MinIO server command. The exact service
override depends on the MinIO package. Confirm the effective command with
`systemctl cat minio.service` before you edit it.

Restart MinIO and test the private health endpoint:

```console
$ sudo systemctl restart minio.service
$ curl --fail http://127.0.0.1:9000/minio/health/live
```

## 2. Configure Vapache

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

## 3. Test signed object operations

Replace `ACCESS_KEY` and `SECRET_KEY` with a MinIO test account, then run:

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
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

## Roll back

Restore the previous Vapache route and MinIO public URL, restart MinIO, and
reload Vapache.

<!--
Deployment contract only; not operator instructions.
--scenario minio-proxy
Canonical dimensions: `payload=streaming`, `operation=listing`, `reload=before-read`.
Scenario storage budget: 1024 MiB.
[Scenario](../../tests/deployments/scenarios/minio-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/minio-proxy/driver.py)
-->
