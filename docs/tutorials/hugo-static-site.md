---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-HUGO-001
scenario: hugo-static
---

# Serve a Hugo site from a VPS

This tutorial builds one Hugo site into an immutable release directory and
serves it directly with Vapache. The example domain is `docs.example.test`.

## What you will do

You will build the site, configure a custom error page, protect one directory
with Basic authentication, compress text responses, cache static assets, and
test a Vapache reload.

## Before you start

You need a Linux VPS with Vapache, Hugo, and `htpasswd` installed. Point
`docs.example.test` at the VPS. Replace the example domain and paths with your
own values before you run the commands.

This tutorial uses `/srv/hugo/source` for the Hugo project and
`/srv/www/hugo/releases/2026-11-08/public` for the generated release.

## 1. Build an immutable release

Run Hugo as the identity that deploys the site:

```console
$ sudo -u deploy hugo \
    --source /srv/hugo/source \
    --destination /srv/www/hugo/releases/2026-11-08/public
$ sudo tee /srv/www/hugo/releases/2026-11-08/public/.htaccess >/dev/null <<'EOF'
RewriteEngine On
RewriteRule ^legacy$ /posts/hello/ [R=302,L]
Header set X-Vapache-Deployment hugo
EOF
$ sudo chown -R deploy:deploy /srv/www/hugo/releases/2026-11-08
$ sudo chmod -R a-w /srv/www/hugo/releases/2026-11-08
```

Create `/srv/www/hugo/releases/2026-11-08/public/404.html` if the Hugo project
does not generate one.

## 2. Create the password and cache paths

Create one test user and a cache directory that the Vapache service identity
can write:

```console
$ sudo install -d -o root -g www-data -m 0750 /etc/vapache/auth
$ sudo htpasswd -c /etc/vapache/auth/hugo.htpasswd alice
$ sudo chown root:www-data /etc/vapache/auth/hugo.htpasswd
$ sudo chmod 0640 /etc/vapache/auth/hugo.htpasswd
$ sudo install -d -o www-data -g www-data -m 0750 /var/cache/vapache/hugo
```

Use the service user from the Apache `User` directive when it is not
`www-data`.

## 3. Configure Vapache

Add this virtual host to the main configuration:

```apache
VapacheCapability AccessFiles On

<VirtualHost *:80>
    ServerName docs.example.test
    DocumentRoot /srv/www/hugo/releases/2026-11-08/public
    DirectoryIndex index.html
    ErrorDocument 404 /404.html

    AddOutputFilterByType BROTLI_COMPRESS text/html text/css application/javascript
    BrotliCompressionQuality 4

    CacheRoot /var/cache/vapache/hugo
    CacheEnable disk /assets/
    CacheHeader On
    CacheIgnoreNoLastMod On
    CacheDefaultExpire 300
    CacheMaxExpire 300

    <Directory /srv/www/hugo/releases/2026-11-08/public>
        AllowOverride FileInfo
        Require all granted
    </Directory>

    <Directory /srv/www/hugo/releases/2026-11-08/public/private>
        AuthType Basic
        AuthName "Private documentation"
        AuthUserFile /etc/vapache/auth/hugo.htpasswd
        Require valid-user
    </Directory>
</VirtualHost>
```

## 4. Test the site

Run:

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ curl --fail http://docs.example.test/
$ curl --silent --show-error --output /tmp/hugo-404.html \
    --write-out '%{http_code}\n' http://docs.example.test/missing
$ curl -I http://docs.example.test/legacy
$ curl -I http://docs.example.test/assets/app.js
$ curl -I http://docs.example.test/assets/app.js
$ curl -I -H 'Accept-Encoding: br' http://docs.example.test/
$ curl -I -H 'Range: bytes=0-31' http://docs.example.test/assets/app.js
$ curl -I http://docs.example.test/private/
$ curl --fail --user alice http://docs.example.test/private/
```

The missing page must return `404`. The legacy path must redirect to
`/posts/hello/`. The asset response must contain `X-Vapache-Deployment: hugo`,
and the second asset request must report an `X-Cache` hit. The compressed
response must name `br`, the range must return `206`, and the unauthenticated
private request must return `401`.

Reload Vapache once more and repeat the home-page and authenticated requests.

## Roll back

Restore the previous virtual host, run `vapachectl configtest`, and reload
Vapache. Keep the generated release until the replacement deployment is
accepted.

<!--
Deployment contract only; not operator instructions.
--scenario hugo-static
Canonical dimensions: `access=basic`, `cache=disk`, `encoding=brotli`, `reload=after-start`.
Scenario storage budget: 768 MiB.
[Scenario](../../tests/deployments/scenarios/hugo-static/scenario.toml)
[Driver](../../tests/deployments/scenarios/hugo-static/driver.py)
-->
