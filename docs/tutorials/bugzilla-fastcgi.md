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

You will install MariaDB, Bugzilla, and `fcgiwrap`, create a dedicated FastCGI
socket, map Bugzilla CGI programs and path information, deny direct access to
source files, test the REST endpoint, and keep an authenticated session across
reload.

## Before you start

Complete [Prepare a Debian VPS for a httpd-rs
tutorial](prepare-debian-vps.md). Point `bugs.example.test` at the VPS and open
TCP ports 80 and 443 in the provider firewall. This Debian 13 example uses
`www-data` user ID `33`; the identity check below verifies that value.

## 1. Install Bugzilla and its database

```console
$ sudo apt install build-essential fcgiwrap git libmariadb-dev mariadb-server \
    perl spawn-fcgi
$ sudo adduser --system --group --home /var/lib/bugzilla-deploy \
    bugzilla-deploy
$ id -u www-data
33
$ sudo install -d -o root -g root -m 0755 /srv/bugzilla
$ sudo install -d -o bugzilla-deploy -g bugzilla-deploy -m 0755 \
    /srv/bugzilla/current
$ sudo -H -u bugzilla-deploy git clone https://github.com/bugzilla/bugzilla.git \
    /srv/bugzilla/current
$ sudo -H -u bugzilla-deploy git -C /srv/bugzilla/current checkout \
    852cd06ef751cb5a5f87e100466e71e46e3cfc0e
$ cd /srv/bugzilla/current
$ sudo -H -u bugzilla-deploy perl install-module.pl --all
$ sudo -H -u bugzilla-deploy perl checksetup.pl
```

The first `checksetup.pl` run creates `localconfig` and reports the remaining
setup work. `install-module.pl` installs CPAN modules inside the Bugzilla tree;
it does not install them globally. Do not continue if `id -u` reports a value
other than `33`.

Create the database and replace both password examples with one new database
password:

```sql
$ sudo mariadb
CREATE DATABASE bugs CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'bugs'@'localhost' IDENTIFIED BY 'replace-database-password';
GRANT ALL PRIVILEGES ON bugs.* TO 'bugs'@'localhost';
EXIT;
```

Set these values in `/srv/bugzilla/current/localconfig`:

```perl
$db_driver = 'mysql';
$db_name = 'bugs';
$db_user = 'bugs';
$db_pass = 'replace-database-password';
$webservergroup = 'www-data';
$urlbase = 'https://bugs.example.test/';
```

Run setup again. Enter the administrator email, name, and password when
`checksetup.pl` asks for them.

```console
$ cd /srv/bugzilla/current
$ sudo -H -u bugzilla-deploy perl checksetup.pl
$ sudo chown -R root:root /srv/bugzilla/current
$ sudo chown -R www-data:www-data /srv/bugzilla/current/data
$ sudo chown root:www-data /srv/bugzilla/current/localconfig
$ sudo chmod 0640 /srv/bugzilla/current/localconfig
```

The deployment identity runs Bugzilla and CPAN setup code. The completed
application becomes root-owned. The FastCGI identity can write only Bugzilla's
data directory.

## 2. Create the FastCGI socket

Create `/etc/systemd/system/bugzilla-fcgi.socket`:

```systemd
[Unit]
Description=Bugzilla FastCGI socket

[Socket]
ListenStream=/run/fcgiwrap/bugzilla.sock
SocketUser=www-data
SocketGroup=www-data
SocketMode=0660
DirectoryMode=0755

[Install]
WantedBy=sockets.target
```

Create `/etc/systemd/system/bugzilla-fcgi.service`:

```systemd
[Unit]
Description=Bugzilla FastCGI worker
Requires=bugzilla-fcgi.socket
After=bugzilla-fcgi.socket

[Service]
User=www-data
Group=www-data
ExecStart=/usr/sbin/fcgiwrap -f
StandardInput=socket
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/srv/bugzilla/current/data
```

Enable the socket and verify its identity:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now bugzilla-fcgi.socket
$ sudo stat -Lc '%F %u:%g %a %n' /run/fcgiwrap/bugzilla.sock
socket 33:33 660 /run/fcgiwrap/bugzilla.sock
```

## 3. Configure httpd-rs

Create `/etc/apache2/sites-available/bugzilla.conf` with a temporary HTTP-only
host, enable it, and obtain the certificate:

```apache
<VirtualHost *:80>
    ServerName bugs.example.test
</VirtualHost>
```

```console
$ sudo a2ensite bugzilla.conf
$ sudo httpd-rsctl configtest
$ sudo systemctl reload httpd-rs.service
$ sudo certbot certonly --apache --domain bugs.example.test
```

Replace it with the final configuration:

```apache
HttpdRsCapability FastCgi On
HttpdRsFastCGIStablePath On unix:/run/fcgiwrap/bugzilla.sock 33 33 0

<VirtualHost *:80>
    ServerName bugs.example.test
    Redirect permanent / https://bugs.example.test/
</VirtualHost>

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

Test the configuration, reload httpd-rs, and verify renewal:

```console
$ sudo httpd-rsctl configtest
$ sudo systemctl reload httpd-rs.service
$ sudo certbot renew --dry-run
```

## 4. Test Bugzilla

```console
$ curl --fail https://bugs.example.test/rest/version
$ curl -I https://bugs.example.test/localconfig
```

The REST request must return Bugzilla version data, and the `localconfig`
request must be denied. Sign in to Bugzilla, open an administration page, reload
httpd-rs, and confirm that the same session can still open the page.

<!--
Deployment contract only; not operator instructions.
--scenario bugzilla-fastcgi
Documentation case: `workflow=admin`, `session=authenticated`, `reload=after-login`.
Scenario storage budget: 2048 MiB.
[Scenario](../../tests/deployments/scenarios/bugzilla-fastcgi/scenario.toml)
[Driver](../../tests/deployments/scenarios/bugzilla-fastcgi/driver.py)
-->
