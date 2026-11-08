---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-GRAFANA-001
scenario: grafana-proxy
---

# Put Grafana behind Vapache on a VPS

This tutorial publishes Grafana below `/grafana/` at
`https://monitor.example.test/grafana/`. The same route carries Grafana's HTTP
and WebSocket traffic.

## What you will do

You will install Grafana, bind it to loopback, configure its public URL, add
the Vapache route, check redirects, use Grafana Live, and reconnect after a
reload.

## Before you start

Complete [Prepare a Debian VPS for a Vapache
tutorial](prepare-debian-vps.md). Point `monitor.example.test` at the VPS and
open TCP ports 80 and 443 in the provider firewall.

## 1. Install Grafana and the certificate

Install Grafana from its Debian repository:

```console
$ sudo apt install gnupg
$ sudo install -d -m 0755 /etc/apt/keyrings
$ curl --fail --show-error --location https://apt.grafana.com/gpg.key \
    | gpg --dearmor \
    | sudo tee /etc/apt/keyrings/grafana.gpg >/dev/null
$ echo 'deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main' \
    | sudo tee /etc/apt/sources.list.d/grafana.list >/dev/null
$ sudo apt update
$ sudo apt install grafana
$ sudo certbot certonly --standalone --domain monitor.example.test
```

## 2. Configure Grafana

Set these values in `/etc/grafana/grafana.ini`:

```ini
[server]
protocol = http
http_addr = 127.0.0.1
http_port = 3000
domain = monitor.example.test
root_url = https://monitor.example.test/grafana/
serve_from_sub_path = true
```

Restart Grafana and test its private health endpoint:

```console
$ sudo systemctl restart grafana-server.service
$ curl --fail http://127.0.0.1:3000/api/health
```

## 3. Configure Vapache

Create `/etc/apache2/sites-available/grafana.conf`:

```apache
<VirtualHost *:443>
    ServerName monitor.example.test
    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/monitor.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/monitor.example.test/privkey.pem

    ProxyPass /grafana/ http://127.0.0.1:3000/grafana/
    ProxyPassReverse /grafana/ http://127.0.0.1:3000/grafana/
</VirtualHost>
```

Enable the virtual host, test the configuration, and start Vapache:

```console
$ sudo a2ensite grafana.conf
$ sudo vapachectl configtest
$ sudo systemctl enable --now vapache.service
```

## 4. Test HTTP and WebSocket behavior

```console
$ curl --fail https://monitor.example.test/grafana/api/health
$ curl -I https://monitor.example.test/grafana/
```

Confirm that every redirect uses the public HTTPS URL and retains `/grafana/`.
Open Grafana Live in a browser and confirm that it receives updates.

Reload Vapache while Grafana Live is open. The existing WebSocket can close
during reload. Confirm that the browser reconnects and resumes receiving
updates.

<!--
Deployment contract only; not operator instructions.
--scenario grafana-proxy
Documentation case: `mount=subpath`, `reload=after-start`, `websocket=message`.
Scenario storage budget: 1024 MiB.
[Scenario](../../tests/deployments/scenarios/grafana-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/grafana-proxy/driver.py)
-->
