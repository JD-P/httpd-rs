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

You will install PostgreSQL, Wagtail, and Gunicorn, create a Wagtail project and
systemd service, configure Django's public authority, add the Vapache route,
test the public site and admin login, reload Vapache, and reuse the session.

## Before you start

Complete [Prepare a Debian VPS for a Vapache
tutorial](prepare-debian-vps.md). Point `cms.example.test` at the VPS and open
TCP ports 80 and 443 in the provider firewall.

## 1. Install Wagtail and PostgreSQL

```console
$ sudo apt install postgresql python3-venv
$ sudo adduser --system --group --home /srv/wagtail wagtail
$ sudo -u postgres createuser wagtail
$ sudo -u postgres createdb --owner=wagtail wagtail
$ sudo python3 -m venv /opt/wagtail
$ sudo /opt/wagtail/bin/pip install --upgrade pip wagtail gunicorn 'psycopg[binary]'
$ sudo -u wagtail /opt/wagtail/bin/wagtail start mysite /srv/wagtail/current
$ sudo certbot certonly --standalone --domain cms.example.test
```

In `/srv/wagtail/current/mysite/settings/base.py`, replace the generated
`DATABASES` value with:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'wagtail',
        'USER': 'wagtail',
    }
}
```

## 2. Configure Django and create the database

Add these values to `/srv/wagtail/current/mysite/settings/production.py`:

```python
ALLOWED_HOSTS = ['cms.example.test']
CSRF_TRUSTED_ORIGINS = ['https://cms.example.test']
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
```

Initialize the database and create the administrator used in the final test:

```console
$ sudo -u wagtail env DJANGO_SETTINGS_MODULE=mysite.settings.production \
    /opt/wagtail/bin/python /srv/wagtail/current/manage.py migrate
$ sudo -u wagtail env DJANGO_SETTINGS_MODULE=mysite.settings.production \
    /opt/wagtail/bin/python /srv/wagtail/current/manage.py createsuperuser
$ sudo -u wagtail env DJANGO_SETTINGS_MODULE=mysite.settings.production \
    /opt/wagtail/bin/python /srv/wagtail/current/manage.py collectstatic --noinput
```

Create `/etc/systemd/system/wagtail-gunicorn.service`:

```systemd
[Unit]
Description=Wagtail Gunicorn service
After=network.target postgresql.service

[Service]
User=wagtail
Group=wagtail
WorkingDirectory=/srv/wagtail/current
Environment=DJANGO_SETTINGS_MODULE=mysite.settings.production
ExecStart=/opt/wagtail/bin/gunicorn --bind 127.0.0.1:8000 mysite.wsgi:application
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Start Gunicorn and test the private endpoint:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now wagtail-gunicorn.service
$ curl -I -H 'Host: cms.example.test' http://127.0.0.1:8000/
```

## 3. Configure Vapache

Create `/etc/apache2/sites-available/wagtail.conf`:

```apache
<VirtualHost *:443>
    ServerName cms.example.test
    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/cms.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/cms.example.test/privkey.pem

    Alias /static/ /srv/wagtail/current/static/
    <Directory /srv/wagtail/current/static>
        Require all granted
    </Directory>

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/
</VirtualHost>
```

Enable the virtual host, test the configuration, and start Vapache:

```console
$ sudo a2ensite wagtail.conf
$ sudo vapachectl configtest
$ sudo systemctl enable --now vapache.service
```

## 4. Test the site and admin session

```console
$ curl --fail https://cms.example.test/
```

Sign in to Wagtail administration through the public URL and open a page-edit
screen. Reload Vapache and open the dashboard with the same session. Confirm
that redirects and form targets use `https://cms.example.test` and never expose
port `8000`.

The `/static/` request is served by Vapache rather than Gunicorn. Confirm that
the Wagtail administration page loads its style sheets after the reload.

<!--
Deployment contract only; not operator instructions.
--scenario wagtail-proxy
Documentation case: `workers=one`, `workflow=admin`, `reload=after-login`.
Scenario storage budget: 3072 MiB.
[Scenario](../../tests/deployments/scenarios/wagtail-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/wagtail-proxy/driver.py)
-->
