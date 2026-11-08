---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-DRUPAL-001
scenario: drupal-fpm
---

# Run Drupal with PHP-FPM on a VPS

This tutorial serves a Composer-installed Drupal site from
`/srv/drupal/current/web` through `/run/php/drupal-fpm.sock`. The example domain
is `drupal.example.test`.

## What you will do

You will install MariaDB, PHP-FPM, Composer, and Drupal, configure a dedicated
PHP-FPM pool, set Drupal's trusted host, connect Vapache, check the release's
access-file rules, and test a reload.

## Before you start

Complete [Prepare a Debian VPS for a Vapache
tutorial](prepare-debian-vps.md). Point `drupal.example.test` at the VPS and
open TCP ports 80 and 443 in the provider firewall. This Debian 13 example uses
PHP-FPM user ID `33`; the identity check below verifies that value.

## 1. Install Drupal and its database

```console
$ sudo apt install composer mariadb-server php8.4-cli php8.4-curl php8.4-fpm \
    php8.4-gd php8.4-mbstring php8.4-mysql php8.4-xml php8.4-zip unzip
$ id -u www-data
33
$ sudo adduser --system --group --home /srv/drupal drupal-deploy
```

Do not continue if `id -u` reports a value other than `33`.

Create the database and replace both password examples with one new database
password:

```sql
$ sudo mariadb
CREATE DATABASE drupal CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'drupal'@'localhost' IDENTIFIED BY 'replace-database-password';
GRANT ALL PRIVILEGES ON drupal.* TO 'drupal'@'localhost';
EXIT;
```

Install Drupal and Drush, then run the standard-profile installer:

```console
$ sudo install -d -o drupal-deploy -g drupal-deploy -m 0750 /srv/drupal
$ sudo -u drupal-deploy composer create-project \
    drupal/recommended-project:11.2.5 \
    /srv/drupal/current
$ sudo -u drupal-deploy composer --working-dir=/srv/drupal/current \
    require drush/drush
$ sudo /srv/drupal/current/vendor/bin/drush site:install standard -y \
    --root=/srv/drupal/current/web \
    --db-url='mysql://drupal:replace-database-password@localhost/drupal' \
    --site-name='Vapache Drupal tutorial' \
    --account-name=admin --account-pass='replace-admin-password'
$ sudo install -d -o www-data -g www-data -m 0750 \
    /srv/drupal/current/web/sites/default/files
$ sudo chown -R root:root /srv/drupal/current
$ sudo chown -R www-data:www-data \
    /srv/drupal/current/web/sites/default/files
$ sudo chmod -R a-w /srv/drupal/current
$ sudo chmod -R u+rwX /srv/drupal/current/web/sites/default/files
```

## 2. Configure Drupal's public host

Add the public host pattern to `web/sites/default/settings.php`:

```php
$settings['trusted_host_patterns'] = [
  '^drupal\.example\.test$',
];
```

Confirm that the files directory is writable and that `settings.php`, the
Composer files, modules, themes, and PHP code are read-only to PHP-FPM.

Protect `settings.php` after the edit:

```console
$ sudo chown root:www-data /srv/drupal/current/web/sites/default/settings.php
$ sudo chmod 0640 /srv/drupal/current/web/sites/default/settings.php
```

## 3. Configure the PHP-FPM pool

Create `/etc/php/8.4/fpm/pool.d/drupal.conf`:

```ini
[drupal]
user = www-data
group = www-data
listen = /run/php/drupal-fpm.sock
listen.owner = root
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 8
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
```

```console
$ sudo systemctl restart php8.4-fpm.service
$ sudo stat -Lc '%F %u:%g %a %n' /run/php/drupal-fpm.sock
socket 0:33 660 /run/php/drupal-fpm.sock
```

## 4. Configure Vapache

Create `/etc/apache2/sites-available/drupal.conf` with a temporary HTTP-only
host, enable it, and obtain the certificate:

```apache
<VirtualHost *:80>
    ServerName drupal.example.test
</VirtualHost>
```

```console
$ sudo a2ensite drupal.conf
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ sudo certbot certonly --apache --domain drupal.example.test
```

Replace it with the final configuration:

```apache
VapacheCapability AccessFiles On
VapacheCapability FastCgi On
VapacheFastCGIStablePath On unix:/run/php/drupal-fpm.sock 33 0 0

<VirtualHost *:80>
    ServerName drupal.example.test
    Redirect permanent / https://drupal.example.test/
</VirtualHost>

<VirtualHost *:443>
    ServerName drupal.example.test
    DocumentRoot /srv/drupal/current/web
    DirectoryIndex index.php

    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/drupal.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/drupal.example.test/privkey.pem

    ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:/run/php/drupal-fpm.sock|fcgi://localhost/srv/drupal/current/web/"

    <Directory /srv/drupal/current/web>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

## 5. Check the Drupal access file

Run `vapachectl configtest`. If it rejects a directive in Drupal's `.htaccess`,
give your coding agent the exact Drupal release, the complete error, and the
access file. Ask it to preserve each rejected rule in the main configuration
and to provide a request that proves the replacement. Do not accept a change
that only deletes the rule.

Test the configuration, reload Vapache, and verify renewal:

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ sudo certbot renew --dry-run
```

## 6. Test Drupal

```console
$ curl --fail https://drupal.example.test/
$ curl --fail https://drupal.example.test/user/login
$ curl -I https://drupal.example.test/.htaccess
```

The access-file request must be denied. Also test one clean URL and one path
that the Drupal rules protect. Reload Vapache and repeat the login-page request.

<!--
Deployment contract only; not operator instructions.
--scenario drupal-fpm
Documentation case: `profile=standard`, `reload=after-start`, `benchmark=clean-url`.
Scenario storage budget: 1536 MiB.
[Scenario](../../tests/deployments/scenarios/drupal-fpm/scenario.toml)
[Driver](../../tests/deployments/scenarios/drupal-fpm/driver.py)
-->
