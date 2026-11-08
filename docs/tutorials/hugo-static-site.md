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

You need a Linux VPS with Vapache, Hugo, and a certificate for
`docs.example.test`. Point the domain at the VPS. Replace the example domain and
paths with your own values before you run the commands.

This tutorial uses `/srv/hugo/source` for the Hugo project and
`/srv/www/hugo/releases/2026-11-08/public` for the generated release.

## 1. Build an immutable release

Run Hugo as the identity that deploys the site:

```console
$ sudo -u deploy hugo \
    --source /srv/hugo/source \
    --destination /srv/www/hugo/releases/2026-11-08/public
$ sudo chown -R deploy:deploy /srv/www/hugo/releases/2026-11-08
$ sudo chmod -R a-w /srv/www/hugo/releases/2026-11-08
```

Create `/srv/www/hugo/releases/2026-11-08/public/404.html` if the Hugo project
does not generate one.

## 2. Configure Vapache

Add this virtual host to the main configuration:

```apache
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

## 3. Test the site

Run:

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
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
