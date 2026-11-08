---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-GIT-CGI-001
scenario: git-cgi
---

# Serve Gitweb and smart Git HTTP from a VPS

This tutorial publishes Gitweb at `/gitweb` and Git smart HTTP at `/git/`
through Vapache CGI. The example domain is `git.example.test`.

## What you will do

You will install Gitweb and Vapache on a fresh Debian VPS, verify the installed
CGI paths, create one bare repository, configure bounded CGI routes, protect
the routes with Basic authentication, push a commit, and test a reload.

## Before you start

This tutorial starts with a fresh Debian 13 VPS. Point `git.example.test` at
the VPS and open TCP port 80 in the provider firewall. Download the current
Vapache Debian package from the [release
page](https://github.com/JD-P/vapache/releases) to `/tmp/vapache.deb`.

## 1. Install Vapache and Gitweb

Install the Vapache package and the Debian packages used by this deployment:

```console
$ sudo apt update
$ sudo apt install /tmp/vapache.deb apache2 apache2-utils git gitweb libcgi-pm-perl
$ sudo systemctl disable --now apache2.service
```

The Apache package supplies the configuration tree that Vapache reads. It does
not need to run.

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
$ sudo install -d -o root -g www-data -m 0750 /etc/vapache/auth
$ sudo htpasswd -c /etc/vapache/auth/git.htpasswd alice
$ sudo chown root:www-data /etc/vapache/auth/git.htpasswd
$ sudo chmod 0640 /etc/vapache/auth/git.htpasswd
```

The `www-data` identity executes both CGI programs. Membership in `gitwriters`
lets smart HTTP update this repository. Do not add unrelated services or users
to that group.

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

## 4. Configure Vapache

Create `/etc/apache2/sites-available/git.conf` with this virtual host. If
`git --exec-path` printed another directory in step 1, replace both
`/usr/lib/git-core` paths with that directory.

<!-- tested-example: tutorials/git-cgi-vhost.conf -->
```apache
VapacheCapability Cgi On

<VirtualHost *:80>
    ServerName git.example.test

    SetEnv GITWEB_CONFIG /etc/gitweb.conf
    SetEnv GIT_PROJECT_ROOT /srv/git
    SetEnv GIT_HTTP_EXPORT_ALL 1

    ScriptAlias /gitweb /usr/share/gitweb/gitweb.cgi
    ScriptAlias /git/ /usr/lib/git-core/git-http-backend/
    Alias /gitweb-static/ /usr/share/gitweb/static/

    <Location />
        AuthType Basic
        AuthName "Git"
        AuthUserFile /etc/vapache/auth/git.htpasswd
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

Enable the virtual host, test the configuration, and start Vapache:

```console
$ sudo a2ensite git.conf
$ sudo vapachectl configtest
$ sudo systemctl enable --now vapache.service
```

## 5. Test browsing, cloning, and pushing

```console
$ curl --fail --user alice http://git.example.test/gitweb
$ git clone http://alice@git.example.test/git/example.git /tmp/example-clone
$ cd /tmp/example-clone
$ printf '%s\n' 'Vapache smart HTTP test' > README.md
$ git add README.md
$ git -c user.name='Vapache test' -c user.email='test@example.test' \
    commit -m 'Test smart HTTP'
$ git push -u origin HEAD:main
$ sudo systemctl reload vapache.service
$ git clone http://alice@git.example.test/git/example.git /tmp/example-check
$ cat /tmp/example-check/README.md
Vapache smart HTTP test
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
