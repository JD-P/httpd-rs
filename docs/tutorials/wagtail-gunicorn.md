---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-WAGTAIL-001
scenario: wagtail-proxy
---

# Put Wagtail and Gunicorn behind Vapache on a VPS

This tutorial publishes a Wagtail site from Gunicorn at
`https://cms.example.test/`.

## What you will do

You will bind Gunicorn to loopback, configure Django's public authority, add
the Vapache route, test the Wagtail API and admin login, reload Vapache, and
reuse the session.

## Before you start

You need a Linux VPS with Vapache, a deployed Wagtail project, Gunicorn, its
database, and a certificate for `cms.example.test`. The Gunicorn systemd
service must already start the correct Python environment.

## 1. Configure Django and Gunicorn

Set these Django values:

```python
ALLOWED_HOSTS = ['cms.example.test']
CSRF_TRUSTED_ORIGINS = ['https://cms.example.test']
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
```

Bind Gunicorn to loopback with two workers:

```text
--bind 127.0.0.1:8000 --workers 2
```

Restart the service and test the private endpoint:

```console
$ sudo systemctl restart wagtail-gunicorn.service
$ curl -I -H 'Host: cms.example.test' http://127.0.0.1:8000/
```

## 2. Configure Vapache

```apache
<VirtualHost *:443>
    ServerName cms.example.test
    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/cms.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/cms.example.test/privkey.pem

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/
</VirtualHost>
```

## 3. Test the API and admin session

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ curl --fail https://cms.example.test/api/v2/pages/
```

Sign in to Wagtail administration through the public URL and open a page-edit
screen. Reload Vapache and open the dashboard with the same session. Confirm
that redirects and form targets use `https://cms.example.test` and never expose
port `8000`.

Keep uploaded media in a separate writable directory. The Gunicorn identity
must not modify Python code or its parent directories.

## Roll back

Restore the previous Vapache route and Django public-host settings, restart
Gunicorn, and reload Vapache.

<!--
Deployment contract only; not operator instructions.
--scenario wagtail-proxy
Canonical dimensions: `workers=two`, `workflow=admin`, `reload=after-login`.
Scenario storage budget: 3072 MiB.
[Scenario](../../tests/deployments/scenarios/wagtail-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/wagtail-proxy/driver.py)
-->
