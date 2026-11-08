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

You will configure Drupal's trusted host, connect Vapache to PHP-FPM, check the
release's access-file rules, protect private files, and test a reload.

## Before you start

You need a Linux VPS with Vapache, PHP-FPM, Drupal, and its database already
installed. Keep the Drupal release read-only to PHP-FPM. Give PHP-FPM write
access only to the configured files directory.

The socket example uses backend ID `33`, socket owner ID `0`, and release owner
ID `1001`. Replace these values with the IDs from the VPS.

## 1. Configure Drupal's public host

Add the public host pattern to `web/sites/default/settings.php`:

```php
$settings['trusted_host_patterns'] = [
  '^drupal\.example\.test$',
];
```

Confirm that the files directory is writable and that `settings.php`, the
Composer files, modules, themes, and PHP code are read-only to PHP-FPM.

## 2. Configure Vapache

```apache
VapacheCapability AccessFiles On
VapacheCapability FastCgi On
VapacheFastCGIStablePath On unix:/run/php/drupal-fpm.sock 33 0 0 1001

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

## 3. Check the Drupal access file

Run `vapachectl configtest`. If it rejects a directive in Drupal's `.htaccess`,
give your coding agent the exact Drupal release, the complete error, and the
access file. Ask it to preserve each rejected rule in the main configuration
and to provide a request that proves the replacement. Do not accept a change
that only deletes the rule.

## 4. Test Drupal

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ curl --fail https://drupal.example.test/
$ curl --fail https://drupal.example.test/user/login
$ curl -I https://drupal.example.test/.htaccess
```

The access-file request must be denied. Also test one clean URL and one path
that the Drupal rules protect. Reload Vapache and repeat the login-page request.

<!--
Deployment contract only; not operator instructions.
--scenario drupal-fpm
Canonical dimensions: `profile=demo_umami`, `reload=after-start`, `benchmark=clean-url`.
Scenario storage budget: 1536 MiB.
[Scenario](../../tests/deployments/scenarios/drupal-fpm/scenario.toml)
[Driver](../../tests/deployments/scenarios/drupal-fpm/driver.py)
-->
