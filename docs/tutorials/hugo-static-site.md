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

You will build the site into a read-only release, serve it over HTTPS, configure
a custom error page and Brotli compression, and test byte ranges and reload.

## Before you start

Complete [Prepare a Debian VPS for a Vapache
tutorial](prepare-debian-vps.md). Point `docs.example.test` at the VPS and open
TCP ports 80 and 443 in the provider firewall. Replace the example domain and
paths with your own values before you run the commands.

This tutorial uses `/srv/hugo/source` for the Hugo project and
`/srv/www/hugo/releases/2026-11-08/public` for the generated release.

## 1. Install Hugo and create the example site

```console
$ sudo apt install hugo
$ sudo adduser --system --group --home /srv/hugo deploy
$ sudo -u deploy hugo new site /srv/hugo/source
$ sudo -u deploy mkdir -p /srv/hugo/source/content /srv/hugo/source/layouts \
    /srv/hugo/source/static/assets
$ printf '%s\n' '---' 'title: Home' '---' 'Vapache Hugo tutorial.' \
    | sudo -u deploy tee /srv/hugo/source/content/_index.md >/dev/null
$ printf '%s\n' '<!doctype html><title>{{ .Title }}</title><main>{{ .Content }}</main>' \
    | sudo -u deploy tee /srv/hugo/source/layouts/home.html >/dev/null
$ printf '%s\n' '<!doctype html><title>Not found</title><h1>Not found</h1>' \
    | sudo -u deploy tee /srv/hugo/source/layouts/404.html >/dev/null
$ printf '%s\n' "console.log('Vapache Hugo tutorial');" \
    | sudo -u deploy tee /srv/hugo/source/static/assets/app.js >/dev/null
```

## 2. Build an immutable release

Run Hugo as the identity that deploys the site:

```console
$ sudo install -d -o deploy -g deploy -m 0755 /srv/www/hugo/releases
$ sudo -u deploy hugo \
    --source /srv/hugo/source \
    --destination /srv/www/hugo/releases/2026-11-08/public
$ sudo chown -R deploy:deploy /srv/www/hugo/releases/2026-11-08
$ sudo chmod -R a-w /srv/www/hugo/releases/2026-11-08
```

Confirm that Hugo generated the files used by the checks:

```console
$ test -f /srv/www/hugo/releases/2026-11-08/public/index.html
$ test -f /srv/www/hugo/releases/2026-11-08/public/404.html
$ test -f /srv/www/hugo/releases/2026-11-08/public/assets/app.js
```

## 3. Configure Vapache

Create `/etc/apache2/sites-available/hugo.conf` with this temporary HTTP-only
virtual host:

```apache
<VirtualHost *:80>
    ServerName docs.example.test
</VirtualHost>
```

Enable it, reload Vapache, and obtain the certificate:

```console
$ sudo a2ensite hugo.conf
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ sudo certbot certonly --apache --domain docs.example.test
```

Replace the temporary host with the final HTTP redirect and HTTPS host:

```apache
<VirtualHost *:80>
    ServerName docs.example.test
    Redirect permanent / https://docs.example.test/
</VirtualHost>

<VirtualHost *:443>
    ServerName docs.example.test
    DocumentRoot /srv/www/hugo/releases/2026-11-08/public
    DirectoryIndex index.html
    ErrorDocument 404 /404.html

    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/docs.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/docs.example.test/privkey.pem

    AddOutputFilterByType BROTLI_COMPRESS text/html text/css application/javascript
    BrotliCompressionQuality 4

    <Directory /srv/www/hugo/releases/2026-11-08/public>
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
```

Test the configuration, reload Vapache, and verify renewal:

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ sudo certbot renew --dry-run
```

## 4. Test the site

Run:

```console
$ curl --fail https://docs.example.test/
$ curl --silent --show-error --output /tmp/hugo-404.html \
    --write-out '%{http_code}\n' https://docs.example.test/missing
$ curl --fail --header 'Accept-Encoding: br' \
    --dump-header /tmp/hugo-brotli.headers \
    --output /tmp/hugo-home.br https://docs.example.test/
$ grep -i '^content-encoding: br' /tmp/hugo-brotli.headers
$ curl --fail --range 0-31 --output /tmp/hugo-range.bin \
    https://docs.example.test/assets/app.js
$ wc -c /tmp/hugo-range.bin
32 /tmp/hugo-range.bin
```

Replace `/assets/app.js` with a generated static asset when the site uses a
different path. The missing page must return `404`, the response header must
name the `br` content encoding, and the range file must contain 32 bytes.

Reload Vapache once more and repeat the home-page and range requests.

<!--
Deployment contract only; not operator instructions.
--scenario hugo-static
Documentation case: `access=open`, `cache=off`, `encoding=brotli`, `reload=after-start`.
Scenario storage budget: 768 MiB.
[Scenario](../../tests/deployments/scenarios/hugo-static/scenario.toml)
[Driver](../../tests/deployments/scenarios/hugo-static/driver.py)
-->
