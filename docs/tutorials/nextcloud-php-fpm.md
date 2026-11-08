---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-NEXTCLOUD-001
scenario: nextcloud-fpm
---

# Run Nextcloud with PHP-FPM on a VPS

This tutorial installs Nextcloud at `/srv/nextcloud/current` and serves it through
`/run/php/nextcloud-fpm.sock`. Nextcloud data remains outside the application
release at `/srv/nextcloud/data`.

## What you will do

You will install MariaDB, PHP-FPM, and Nextcloud, configure a dedicated PHP-FPM
pool and the public URL, deny direct access to private trees, upload and move a
WebDAV object, reload Vapache, and verify the downloaded bytes.

## Before you start

Complete [Prepare a Debian VPS for a Vapache
tutorial](prepare-debian-vps.md). Point `cloud.example.test` at the VPS and open
TCP ports 80 and 443 in the provider firewall. This Debian 13 example uses
PHP-FPM user ID `33`; the identity check below verifies that value.

## 1. Install Nextcloud and its database

```console
$ sudo apt install bzip2 mariadb-server php8.4-bcmath php8.4-bz2 php8.4-cli \
    php8.4-curl php8.4-fpm php8.4-gd php8.4-gmp php8.4-intl php8.4-mbstring \
    php8.4-mysql php8.4-xml php8.4-zip
$ id -u www-data
33
$ curl --fail --show-error --location \
    --output /tmp/nextcloud.tar.bz2 \
    https://download.nextcloud.com/server/releases/nextcloud-32.0.1.tar.bz2
$ printf '%s  %s\n' \
    5810b06e75678384973d8d86387ee39f4c086d79dfa92f15fcb743aaba36eaa9 \
    /tmp/nextcloud.tar.bz2 | sha256sum --check --strict
$ sudo install -d -o root -g root -m 0755 /srv/nextcloud/current
$ sudo tar --extract --bzip2 --file /tmp/nextcloud.tar.bz2 \
    --strip-components=1 --directory /srv/nextcloud/current
$ sudo install -d -o www-data -g www-data -m 0750 /srv/nextcloud/data
$ sudo chown -R www-data:www-data /srv/nextcloud/current/config
```

Do not continue if `id -u` reports a value other than `33`.

Create the database and replace both password examples with one new database
password:

```sql
$ sudo mariadb
CREATE DATABASE nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'nextcloud'@'localhost' IDENTIFIED BY 'replace-database-password';
GRANT ALL PRIVILEGES ON nextcloud.* TO 'nextcloud'@'localhost';
EXIT;
```

Read the administrator password without saving it in shell history, pass it
through the environment, install Nextcloud, and then remove the variable:

```console
$ read -rsp 'Nextcloud administrator password: ' OC_PASS; echo
$ export OC_PASS
$ sudo --preserve-env=OC_PASS -u www-data \
    php /srv/nextcloud/current/occ maintenance:install \
    --database=mysql --database-name=nextcloud --database-user=nextcloud \
    --database-pass='replace-database-password' \
    --admin-user=admin --admin-pass-from-env \
    --data-dir=/srv/nextcloud/data
$ unset OC_PASS
```

## 2. Configure Nextcloud

Run these commands as the PHP-FPM identity:

```console
$ sudo -u www-data php /srv/nextcloud/current/occ config:system:set trusted_domains 1 --value=cloud.example.test
$ sudo -u www-data php /srv/nextcloud/current/occ config:system:set overwriteprotocol --value=https
$ sudo -u www-data php /srv/nextcloud/current/occ config:system:get datadirectory
/srv/nextcloud/data
```

Do not continue if the last command reports a different directory. Keep the
release and `config.php` read-only to PHP-FPM after configuration.

Protect the application after configuration:

```console
$ sudo chown -R root:root /srv/nextcloud/current
$ sudo chown root:www-data /srv/nextcloud/current/config/config.php
$ sudo chmod -R a-w /srv/nextcloud/current
$ sudo chmod 0640 /srv/nextcloud/current/config/config.php
```

## 3. Configure the PHP-FPM pool

Create `/etc/php/8.4/fpm/pool.d/nextcloud.conf`:

```ini
[nextcloud]
user = www-data
group = www-data
listen = /run/php/nextcloud-fpm.sock
listen.owner = root
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 12
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 4
```

```console
$ sudo systemctl restart php8.4-fpm.service
$ sudo stat -Lc '%F %u:%g %a %n' /run/php/nextcloud-fpm.sock
socket 0:33 660 /run/php/nextcloud-fpm.sock
```

## 4. Configure Vapache

Create `/etc/apache2/sites-available/nextcloud.conf` with a temporary HTTP-only
host, enable it, and obtain the certificate:

```apache
<VirtualHost *:80>
    ServerName cloud.example.test
</VirtualHost>
```

```console
$ sudo a2ensite nextcloud.conf
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ sudo certbot certonly --apache --domain cloud.example.test
```

Replace it with the final configuration:

```apache
VapacheCapability FastCgi On
VapacheFastCGIStablePath On unix:/run/php/nextcloud-fpm.sock 33 0 0

<VirtualHost *:80>
    ServerName cloud.example.test
    Redirect permanent / https://cloud.example.test/
</VirtualHost>

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

Test the configuration, reload Vapache, and verify renewal:

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ sudo certbot renew --dry-run
```

## 5. Test a WebDAV workflow

Each `curl --user admin` command prompts for the administrator password. The
password does not appear in the command or shell history.

```console
$ dd if=/dev/urandom of=/tmp/vapache-nextcloud.bin bs=1M count=2
$ curl --fail --user admin -X MKCOL \
    https://cloud.example.test/remote.php/dav/files/admin/vapache-test
$ curl --fail --user admin -T /tmp/vapache-nextcloud.bin \
    https://cloud.example.test/remote.php/dav/files/admin/vapache-test/original.bin
$ curl --fail --user admin -X PROPFIND -H 'Depth: 1' \
    https://cloud.example.test/remote.php/dav/files/admin/vapache-test/
$ curl --fail --user admin -X MOVE \
    -H 'Destination: https://cloud.example.test/remote.php/dav/files/admin/vapache-test/moved.bin' \
    https://cloud.example.test/remote.php/dav/files/admin/vapache-test/original.bin
$ sudo systemctl reload vapache.service
$ curl --fail --user admin -o /tmp/vapache-nextcloud-check.bin \
    https://cloud.example.test/remote.php/dav/files/admin/vapache-test/moved.bin
$ cmp /tmp/vapache-nextcloud.bin /tmp/vapache-nextcloud-check.bin
$ curl --fail --user admin -X DELETE \
    https://cloud.example.test/remote.php/dav/files/admin/vapache-test/moved.bin
$ curl --fail --user admin -X DELETE \
    https://cloud.example.test/remote.php/dav/files/admin/vapache-test
```

Remove the two files in `/tmp` after the final request succeeds.

<!--
Deployment contract only; not operator instructions.
--scenario nextcloud-fpm
Documentation case: `upload=large`, `dav=move`, `reload=before-download`.
Scenario storage budget: 3072 MiB.
[Scenario](../../tests/deployments/scenarios/nextcloud-fpm/scenario.toml)
[Driver](../../tests/deployments/scenarios/nextcloud-fpm/driver.py)
-->
