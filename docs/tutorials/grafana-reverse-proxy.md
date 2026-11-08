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

You will bind Grafana to loopback, configure its public URL, add the Vapache
route, check redirects, use Grafana Live, and reconnect after a reload.

## Before you start

You need a Linux VPS with Vapache, Grafana, and a certificate for
`monitor.example.test`. Grafana must already run as a systemd service.

## 1. Configure Grafana

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

## 2. Configure Vapache

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

## 3. Test HTTP and WebSocket behavior

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
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
Canonical dimensions: `mount=subpath`, `reload=after-start`, `websocket=message`.
Scenario storage budget: 1024 MiB.
[Scenario](../../tests/deployments/scenarios/grafana-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/grafana-proxy/driver.py)
-->
