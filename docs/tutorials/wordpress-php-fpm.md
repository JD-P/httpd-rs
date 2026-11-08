---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-WORDPRESS-001
scenario: wordpress-fpm
---

# Run WordPress with PHP-FPM on a VPS

This tutorial serves WordPress from `/srv/wordpress/current` through the PHP-FPM
socket at `/run/php/wordpress-fpm.sock`. The example domain is
`www.example.test`.

## What you will do

You will separate WordPress code from writable uploads, configure the PHP-FPM
socket, enable pretty permalinks, test an upload and REST request, and reload
Vapache.

## Before you start

You need a Linux VPS with Vapache, PHP-FPM, WordPress, and its database already
installed. Complete [Configure a protected PHP-FPM Unix
socket](../how-to/configure-php-fpm-unix-socket.md) and [Replace an unsafe
writable PHP layout](../how-to/replace-writable-php-layout.md) first.

The examples use PHP-FPM user ID `33`, socket owner ID `0`, and release owner ID
`1001`. Replace them with the values returned by `id -u` and `stat` on the VPS.

## 1. Set the WordPress public URL

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

## 2. Configure Vapache

```apache
VapacheCapability AccessFiles On
VapacheCapability FastCgi On
VapacheFastCGIStablePath On unix:/run/php/wordpress-fpm.sock 33 0 0 1001

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

## 3. Test WordPress

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ curl --fail https://www.example.test/wp-json/
```

In the WordPress dashboard, select a non-plain permalink format and upload one
PNG file. Open the resulting post and media URL. Place a harmless file named
`vapache-test.php` in the upload directory and confirm that an HTTP request for
it is denied rather than executed or returned as source. Remove the file after
the test.

Reload Vapache and repeat the REST and permalink requests.

## Roll back

Restore the previous virtual host and `wp-config.php` values, run the
configuration test, and reload Vapache. Do not restore PHP-FPM write access to
the WordPress code as a rollback method.

<!--
Deployment contract only; not operator instructions.
--scenario wordpress-fpm
Canonical dimensions: `permalinks=pretty`, `asset_cache=disk`, `reload=after-start`.
Scenario storage budget: 2048 MiB.
[Scenario](../../tests/deployments/scenarios/wordpress-fpm/scenario.toml)
[Driver](../../tests/deployments/scenarios/wordpress-fpm/driver.py)
-->
