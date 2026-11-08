---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-WORDPRESS-001
scenario: wordpress-fpm
---

# Run WordPress with PHP-FPM on a VPS

This tutorial installs WordPress at `/srv/wordpress/current` and serves it through the PHP-FPM
socket at `/run/php/wordpress-fpm.sock`. The example domain is
`www.example.test`.

## What you will do

You will install MariaDB, PHP-FPM, and WordPress, separate executable code from
writable uploads, configure the PHP-FPM socket, enable pretty permalinks, test
an upload and REST request, and reload Vapache.

## Before you start

Complete [Prepare a Debian VPS for a Vapache
tutorial](prepare-debian-vps.md). Point `www.example.test` at the VPS and open
TCP ports 80 and 443 in the provider firewall. This Debian 13 example uses
PHP-FPM user ID `33`; the identity check below verifies that value.

## 1. Install MariaDB, PHP-FPM, and WP-CLI

```console
$ sudo apt install mariadb-server php8.4-cli php8.4-curl php8.4-fpm \
    php8.4-gd php8.4-mbstring php8.4-mysql php8.4-xml
$ curl --fail --show-error --location \
    --output /tmp/wp-cli.phar \
    https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
$ curl --fail --show-error --location \
    --output /tmp/wp-cli.phar.asc \
    https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar.asc
$ curl --fail --show-error --location \
    --output /tmp/wp-cli.pgp \
    https://raw.githubusercontent.com/wp-cli/builds/gh-pages/wp-cli.pgp
$ test "$(gpg --show-keys --with-colons /tmp/wp-cli.pgp \
    | awk -F: '$1 == "fpr" { print $10; exit }')" \
    = 63AF7AA15067C05616FDDD88A3A2E8F226F0BC06
$ gpg --batch --import /tmp/wp-cli.pgp
$ gpg --batch --verify /tmp/wp-cli.phar.asc /tmp/wp-cli.phar
$ sudo install -m 0755 /tmp/wp-cli.phar /usr/local/bin/wp
$ id -u www-data
33
```

Do not continue if `id -u` reports a value other than `33`.

Create the database and replace both password examples with one new database
password:

```sql
$ sudo mariadb
CREATE DATABASE wordpress CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'wordpress'@'localhost' IDENTIFIED BY 'replace-database-password';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wordpress'@'localhost';
EXIT;
```

## 2. Install WordPress and separate uploads

```console
$ sudo install -d -o root -g root -m 0755 /srv/wordpress/current
$ sudo wp core download --allow-root --version=6.8.3 \
    --path=/srv/wordpress/current
$ sudo wp config create --allow-root --path=/srv/wordpress/current \
    --dbname=wordpress --dbuser=wordpress --prompt=dbpass
$ sudo wp core install --allow-root --path=/srv/wordpress/current \
    --url=https://www.example.test --title='Vapache WordPress tutorial' \
    --admin_user=admin --admin_email=admin@example.test \
    --prompt=admin_password
$ sudo wp rewrite structure '/%postname%/' --hard --allow-root \
    --path=/srv/wordpress/current
$ sudo install -d -o www-data -g www-data -m 0750 \
    /srv/wordpress/shared/uploads
$ sudo install -d -o root -g root -m 0755 \
    /srv/wordpress/current/wp-content/uploads
$ sudo chown -R root:root /srv/wordpress/current
$ sudo chmod -R a-w /srv/wordpress/current
$ sudo chown root:www-data /srv/wordpress/current/wp-config.php
$ sudo chmod 0640 /srv/wordpress/current/wp-config.php
$ sudo mount --bind /srv/wordpress/shared/uploads \
    /srv/wordpress/current/wp-content/uploads
$ echo '/srv/wordpress/shared/uploads /srv/wordpress/current/wp-content/uploads none bind 0 0' \
    | sudo tee -a /etc/fstab >/dev/null
```

The bind mount keeps uploaded data writable without making the WordPress PHP
files writable.

## 3. Configure the PHP-FPM pool

Create `/etc/php/8.4/fpm/pool.d/wordpress.conf`:

```ini
[wordpress]
user = www-data
group = www-data
listen = /run/php/wordpress-fpm.sock
listen.owner = root
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 8
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
```

Restart PHP-FPM and verify the socket identity:

```console
$ sudo systemctl restart php8.4-fpm.service
$ sudo stat -Lc '%F %u:%g %a %n' /run/php/wordpress-fpm.sock
socket 0:33 660 /run/php/wordpress-fpm.sock
```

## 4. Set the WordPress public URL

Set the public HTTPS URL in `wp-config.php`:

```php
define('WP_HOME', 'https://www.example.test');
define('WP_SITEURL', 'https://www.example.test');
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
```

Keep `/srv/wordpress/current` read-only to PHP-FPM. Give PHP-FPM write access to
`/srv/wordpress/shared/uploads`, and make `wp-content/uploads` refer to that
writable data path through the deployment process.

## 5. Configure Vapache

Create `/etc/apache2/sites-available/wordpress.conf` with a temporary HTTP-only
host, enable it, and obtain the certificate:

```apache
<VirtualHost *:80>
    ServerName www.example.test
</VirtualHost>
```

```console
$ sudo a2ensite wordpress.conf
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ sudo certbot certonly --apache --domain www.example.test
```

Replace it with the final configuration:

```apache
VapacheCapability AccessFiles On
VapacheCapability FastCgi On
VapacheFastCGIStablePath On unix:/run/php/wordpress-fpm.sock 33 0 0

<VirtualHost *:80>
    ServerName www.example.test
    Redirect permanent / https://www.example.test/
</VirtualHost>

<VirtualHost *:443>
    ServerName www.example.test
    DocumentRoot /srv/wordpress/current
    DirectoryIndex index.php

    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/www.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/www.example.test/privkey.pem

    ProxyPassMatch ^/(.*\.php(/.*)?)$ "unix:/run/php/wordpress-fpm.sock|fcgi://localhost/srv/wordpress/current/"

    <Directory /srv/wordpress/current>
        AllowOverride FileInfo
        Require all granted
    </Directory>

    <Directory /srv/wordpress/current/wp-content/uploads>
        <FilesMatch "\.php$">
            Require all denied
        </FilesMatch>
    </Directory>
</VirtualHost>
```

Test the configuration, reload Vapache, and verify renewal:

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ sudo certbot renew --dry-run
```

## 6. Test WordPress

```console
$ curl --fail https://www.example.test/wp-json/
```

In the WordPress dashboard, upload one PNG file and create a post that uses the
pretty permalink configured in step 2. Open the resulting post and media URL.
Place a harmless file named `vapache-test.php` in the upload directory and
confirm that an HTTP request for it is denied rather than executed or returned
as source. Remove the file after the test.

Reload Vapache and repeat the REST and permalink requests.

<!--
Deployment contract only; not operator instructions.
--scenario wordpress-fpm
Documentation case: `permalinks=pretty`, `asset_cache=off`, `reload=after-start`.
Scenario storage budget: 2048 MiB.
[Scenario](../../tests/deployments/scenarios/wordpress-fpm/scenario.toml)
[Driver](../../tests/deployments/scenarios/wordpress-fpm/driver.py)
-->
