---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-GIT-CGI-001
scenario: git-cgi
---

# Serve Gitweb and smart Git HTTP from a VPS

This tutorial publishes Gitweb at `/gitweb` and Git smart HTTP at `/git/`
through httpd-rs CGI. The example domain is `git.example.test`.

## What you will do

You will install Gitweb on a prepared Debian VPS, verify the installed CGI
paths, create one bare repository, obtain a certificate, configure bounded CGI
routes, protect the routes with HTTPS and Basic authentication, push a commit,
and test a reload.

## Before you start

Complete [Prepare a Debian VPS for a httpd-rs
tutorial](prepare-debian-vps.md). Point `git.example.test` at the VPS and open
TCP ports 80 and 443 in the provider firewall.

## 1. Install Gitweb

Install the Debian packages used by this deployment:

```console
$ sudo apt install apache2-utils git gitweb libcgi-pm-perl
```

Verify the three paths used later in the virtual host:

```console
$ test -x /usr/share/gitweb/gitweb.cgi
$ test -d /usr/share/gitweb/static
$ git --exec-path
/usr/lib/git-core
$ test -x "$(git --exec-path)/git-http-backend"
```

Do not continue if one of the `test` commands fails. Use the path printed by
`git --exec-path` in the virtual host if it differs from
`/usr/lib/git-core`.

## 2. Create the service identities and repository

```console
$ sudo addgroup --system gitwriters
$ sudo adduser --system --group --home /nonexistent --no-create-home git
$ sudo adduser git gitwriters
$ sudo adduser www-data gitwriters
$ sudo install -d -o git -g gitwriters -m 2770 /srv/git
$ sudo -u git git init --bare --shared=group /srv/git/example.git
$ sudo -u git git -C /srv/git/example.git symbolic-ref HEAD refs/heads/main
$ sudo -u git git -C /srv/git/example.git config http.receivepack true
$ sudo install -d -o root -g www-data -m 0750 /etc/httpd-rs/auth
$ sudo htpasswd -B -C 12 -c /etc/httpd-rs/auth/git.htpasswd alice
$ sudo chown root:www-data /etc/httpd-rs/auth/git.htpasswd
$ sudo chmod 0640 /etc/httpd-rs/auth/git.htpasswd
```

The `www-data` identity executes both CGI programs. Membership in `gitwriters`
lets every authenticated user update every repository in `/srv/git`; this
tutorial therefore implements one shared authorization tier. Use Gitea or
another forge when you need per-user or per-repository authorization. Do not
add unrelated services or users to `gitwriters`.

## 3. Configure Gitweb

Create `/etc/gitweb.conf`:

```perl
$projectroot = "/srv/git";
$git_temp = "/var/cache/gitweb";
```

Create the cache directory and protect the configuration file:

```console
$ sudo chown root:root /etc/gitweb.conf
$ sudo chmod 0644 /etc/gitweb.conf
$ sudo install -d -o www-data -g www-data -m 0750 /var/cache/gitweb
```

## 4. Configure httpd-rs

First create `/etc/apache2/sites-available/git.conf` with an HTTP-only virtual
host that Certbot can use:

```apache
<VirtualHost *:80>
    ServerName git.example.test
</VirtualHost>
```

Enable it, reload httpd-rs, and obtain the certificate through httpd-rs's
Certbot control shim:

```console
$ sudo a2ensite git.conf
$ sudo httpd-rsctl configtest
$ sudo systemctl reload httpd-rs.service
$ sudo certbot certonly --apache --domain git.example.test
```

Replace the temporary virtual host with the following configuration. If
`git --exec-path` printed another directory in step 1, replace both
`/usr/lib/git-core` paths with that directory.

<!-- tested-example: tutorials/git-cgi-vhost.conf -->
```apache
HttpdRsCapability Cgi On

<VirtualHost *:80>
    ServerName git.example.test
    Redirect permanent / https://git.example.test/
</VirtualHost>

<VirtualHost *:443>
    ServerName git.example.test

    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/git.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/git.example.test/privkey.pem

    SetEnv GITWEB_CONFIG /etc/gitweb.conf
    SetEnv GIT_PROJECT_ROOT /srv/git
    SetEnv GIT_HTTP_EXPORT_ALL 1

    ScriptAlias /gitweb /usr/share/gitweb/gitweb.cgi
    ScriptAlias /git/ /usr/lib/git-core/git-http-backend/
    Alias /gitweb-static/ /usr/share/gitweb/static/

    <Location />
        AuthType Basic
        AuthName "Git"
        AuthUserFile /etc/httpd-rs/auth/git.htpasswd
        Require valid-user
    </Location>

    <Directory /usr/share/gitweb>
        Options ExecCGI
        Require all granted
    </Directory>
    <Directory /usr/lib/git-core>
        Options ExecCGI
        Require all granted
    </Directory>
</VirtualHost>
```

Test the final configuration, reload httpd-rs, and test certificate renewal:

```console
$ sudo httpd-rsctl configtest
$ sudo systemctl reload httpd-rs.service
$ sudo certbot renew --dry-run
```

## 5. Test browsing, cloning, and pushing

```console
$ curl --fail --user alice https://git.example.test/gitweb
$ git clone https://alice@git.example.test/git/example.git /tmp/example-clone
$ cd /tmp/example-clone
$ printf '%s\n' 'httpd-rs smart HTTP test' > README.md
$ git add README.md
$ git -c user.name='httpd-rs test' -c user.email='test@example.test' \
    commit -m 'Test smart HTTP'
$ git push -u origin HEAD:main
$ sudo systemctl reload httpd-rs.service
$ git clone https://alice@git.example.test/git/example.git /tmp/example-check
$ cat /tmp/example-check/README.md
httpd-rs smart HTTP test
```

Enter Alice's password when Git asks for it. A successful Gitweb page alone
does not test smart-HTTP request bodies. The push and second clone test the
write and read paths across a reload.

Remove `/tmp/example-clone` and `/tmp/example-check` after the test succeeds.

<!--
Deployment contract only; not operator instructions.
--scenario git-cgi
Documentation case: `application=smart-http`, `access=basic`, `reload=after-start`.
Scenario storage budget: 512 MiB.
[Scenario](../../tests/deployments/scenarios/git-cgi/scenario.toml)
[Driver](../../tests/deployments/scenarios/git-cgi/driver.py)
-->
