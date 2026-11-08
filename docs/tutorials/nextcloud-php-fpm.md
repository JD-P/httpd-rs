---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-NEXTCLOUD-001
scenario: nextcloud-fpm
---

# Run Nextcloud with PHP-FPM on a VPS

This tutorial serves Nextcloud from `/srv/nextcloud/current` through
`/run/php/nextcloud-fpm.sock`. Nextcloud data remains outside the application
release at `/srv/nextcloud/data`.

## What you will do

You will configure the public URL, protect the PHP-FPM socket, deny direct
access to private trees, upload and move a WebDAV object, reload Vapache, and
verify the downloaded bytes.

## Before you start

You need a Linux VPS with Vapache, PHP-FPM, Nextcloud, and its database already
installed. Install Nextcloud with its data directory at `/srv/nextcloud/data`,
or move the data with Nextcloud's documented maintenance procedure before you
continue. The example domain is `cloud.example.test`. The socket example uses
backend ID `33`, socket owner ID `0`, and release owner ID `1001`; replace them
with the IDs from the VPS.

## 1. Configure Nextcloud

Run these commands as the PHP-FPM identity:

```console
$ sudo -u www-data php /srv/nextcloud/current/occ config:system:set trusted_domains 1 --value=cloud.example.test
$ sudo -u www-data php /srv/nextcloud/current/occ config:system:set overwriteprotocol --value=https
$ sudo -u www-data php /srv/nextcloud/current/occ config:system:get datadirectory
/srv/nextcloud/data
```

Do not continue if the last command reports a different directory. Keep the
release and `config.php` read-only to PHP-FPM after configuration.

## 2. Configure Vapache

```apache
VapacheCapability FastCgi On
VapacheFastCGIStablePath On unix:/run/php/nextcloud-fpm.sock 33 0 0 1001

<VirtualHost *:443>
    ServerName cloud.example.test
    DocumentRoot /srv/nextcloud/current
    DirectoryIndex index.php

    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/cloud.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/cloud.example.test/privkey.pem

    ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:/run/php/nextcloud-fpm.sock|fcgi://localhost/srv/nextcloud/current/"

    <Directory /srv/nextcloud/current>
        AllowOverride None
        CGIPassAuth On
        Require all granted
    </Directory>
    <Directory /srv/nextcloud/current/config>
        Require all denied
    </Directory>
    <Directory /srv/nextcloud/data>
        Require all denied
    </Directory>
    <Directory /srv/nextcloud/current/lib>
        Require all denied
    </Directory>
</VirtualHost>
```

## 3. Test a WebDAV workflow

Replace `alice` and the password in these commands with a Nextcloud test
account:

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ dd if=/dev/urandom of=/tmp/vapache-nextcloud.bin bs=1M count=2
$ curl --fail --user alice:password -X MKCOL \
    https://cloud.example.test/remote.php/dav/files/alice/vapache-test
$ curl --fail --user alice:password -T /tmp/vapache-nextcloud.bin \
    https://cloud.example.test/remote.php/dav/files/alice/vapache-test/original.bin
$ curl --fail --user alice:password -X PROPFIND -H 'Depth: 1' \
    https://cloud.example.test/remote.php/dav/files/alice/vapache-test/
$ curl --fail --user alice:password -X MOVE \
    -H 'Destination: https://cloud.example.test/remote.php/dav/files/alice/vapache-test/moved.bin' \
    https://cloud.example.test/remote.php/dav/files/alice/vapache-test/original.bin
$ sudo systemctl reload vapache.service
$ curl --fail --user alice:password -o /tmp/vapache-nextcloud-check.bin \
    https://cloud.example.test/remote.php/dav/files/alice/vapache-test/moved.bin
$ cmp /tmp/vapache-nextcloud.bin /tmp/vapache-nextcloud-check.bin
```

Delete the test object and collection after `cmp` succeeds.

<!--
Deployment contract only; not operator instructions.
--scenario nextcloud-fpm
Canonical dimensions: `upload=large`, `dav=move`, `reload=before-download`.
Scenario storage budget: 3072 MiB.
[Scenario](../../tests/deployments/scenarios/nextcloud-fpm/scenario.toml)
[Driver](../../tests/deployments/scenarios/nextcloud-fpm/driver.py)
-->
