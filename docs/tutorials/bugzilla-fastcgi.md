---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-BUGZILLA-001
scenario: bugzilla-fastcgi
---

# Run Bugzilla through FastCGI on a VPS

This tutorial serves Bugzilla from `/srv/bugzilla/current` through the
`fcgiwrap` Unix socket at `/run/fcgiwrap/bugzilla.sock`.

## What you will do

You will protect the FastCGI socket, map Bugzilla CGI programs and path
information, deny direct access to source and configuration files, test the
REST endpoint, and keep an authenticated session across reload.

## Before you start

You need a Linux VPS with Vapache, Bugzilla, Perl, `fcgiwrap`, and Bugzilla's
database already installed. Complete Bugzilla's `checksetup.pl` procedure
before you configure Vapache. The example domain is `bugs.example.test`.

This example uses worker ID `33`, socket owner ID `33`, and release owner ID
`1001`. Replace them with the IDs reported on the VPS.

## 1. Protect the Bugzilla release and socket

Keep Bugzilla CGI and Perl files read-only to the `fcgiwrap` worker. Configure
`fcgiwrap` to create `/run/fcgiwrap/bugzilla.sock` with mode `0660`, then run:

```console
$ sudo stat -Lc '%F %u:%g %a %n' /run/fcgiwrap/bugzilla.sock
```

Confirm that the result is a socket and that the reported IDs match the Vapache
configuration below.

## 2. Configure Vapache

```apache
VapacheCapability FastCgi On
VapacheFastCGIStablePath On unix:/run/fcgiwrap/bugzilla.sock 33 33 0 1001

<VirtualHost *:443>
    ServerName bugs.example.test
    DocumentRoot /srv/bugzilla/current
    DirectoryIndex index.cgi

    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/bugs.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/bugs.example.test/privkey.pem

    ProxyFCGIBackendType GENERIC
    ProxyPassMatch ^/(.*\.cgi(/.*)?)$ "unix:/run/fcgiwrap/bugzilla.sock|fcgi://localhost/srv/bugzilla/current/"

    <Directory /srv/bugzilla/current>
        AllowOverride None
        Require all granted
    </Directory>
    <FilesMatch "(\.pm|\.pl|\.tmpl|^localconfig.*)$">
        Require all denied
    </FilesMatch>
</VirtualHost>
```

## 3. Test Bugzilla

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ curl --fail https://bugs.example.test/rest/version
$ curl -I https://bugs.example.test/localconfig
```

The REST request must return Bugzilla version data, and the `localconfig`
request must be denied. Sign in to Bugzilla, open an administration page, reload
Vapache, and confirm that the same session can still open the page.

## Roll back

Restore the previous virtual host and reload Vapache. Stop the dedicated
`fcgiwrap` instance only if no other verified route uses it.

<!--
Deployment contract only; not operator instructions.
--scenario bugzilla-fastcgi
Canonical dimensions: `workflow=admin`, `session=authenticated`, `reload=after-login`.
Scenario storage budget: 2048 MiB.
[Scenario](../../tests/deployments/scenarios/bugzilla-fastcgi/scenario.toml)
[Driver](../../tests/deployments/scenarios/bugzilla-fastcgi/driver.py)
-->
