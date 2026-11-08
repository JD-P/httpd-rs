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

You will create one bare repository, configure bounded CGI routes, protect the
routes with Basic authentication, clone the repository, and test a reload.

## Before you start

You need a Linux VPS with Vapache, Git, Gitweb, Perl, and the Perl CGI module
installed. This example uses Debian-family paths. Confirm the Gitweb and
`git-http-backend` paths supplied by your distribution before you continue.

## 1. Create the repository and password file

```console
$ sudo install -d -o git -g git -m 0750 /srv/git
$ sudo -u git git init --bare /srv/git/example.git
$ sudo -u git git -C /srv/git/example.git symbolic-ref HEAD refs/heads/main
$ sudo -u git git -C /srv/git/example.git config http.receivepack true
$ sudo install -d -o root -g www-data -m 0750 /etc/vapache/auth
$ sudo htpasswd -c /etc/vapache/auth/git.htpasswd alice
$ sudo chown root:www-data /etc/vapache/auth/git.htpasswd
$ sudo chmod 0640 /etc/vapache/auth/git.htpasswd
```

## 2. Configure Gitweb

Create `/etc/gitweb.conf`:

```perl
$projectroot = "/srv/git";
$git_temp = "/var/cache/gitweb";
```

Ensure that the Vapache service identity can read the repositories and that the
`git` identity remains the only identity that can modify them.

## 3. Configure Vapache

Add this virtual host:

```apache
VapacheCapability Cgi On

<VirtualHost *:80>
    ServerName git.example.test

    SetEnv GITWEB_CONFIG /etc/gitweb.conf
    SetEnv GIT_PROJECT_ROOT /srv/git
    SetEnv GIT_HTTP_EXPORT_ALL 1

    ScriptAlias /gitweb /usr/share/gitweb/index.cgi
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

## 4. Test browsing and cloning

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
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
Canonical dimensions: `application=smart-http`, `access=basic`, `reload=after-start`.
Scenario storage budget: 512 MiB.
[Scenario](../../tests/deployments/scenarios/git-cgi/scenario.toml)
[Driver](../../tests/deployments/scenarios/git-cgi/driver.py)
-->
