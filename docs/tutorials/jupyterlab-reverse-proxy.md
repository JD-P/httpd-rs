---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-JUPYTERLAB-001
scenario: jupyterlab-proxy
---

# Put JupyterLab behind Vapache on a VPS

This tutorial publishes JupyterLab below `/jupyter/` at
`https://lab.example.test/jupyter/`. The same Vapache route carries the HTTP API
and kernel WebSocket protocol.

## What you will do

You will bind JupyterLab to loopback, set its base URL, add the Vapache route,
execute code in a kernel, reload Vapache, reconnect, and use the same kernel.

## Before you start

You need a Linux VPS with Vapache, JupyterLab, and a certificate for
`lab.example.test`. Run JupyterLab from a dedicated systemd service and keep its
token or configured authentication enabled.

## 1. Configure JupyterLab

Set these values in the Jupyter Server configuration used by the service:

```python
c.ServerApp.ip = '127.0.0.1'
c.ServerApp.port = 8888
c.ServerApp.base_url = '/jupyter/'
c.ServerApp.open_browser = False
c.ServerApp.trust_xheaders = True
```

Restart JupyterLab and test its private endpoint:

```console
$ sudo systemctl restart jupyterlab.service
$ curl -I http://127.0.0.1:8888/jupyter/
```

## 2. Configure Vapache

```apache
<VirtualHost *:443>
    ServerName lab.example.test
    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/lab.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/lab.example.test/privkey.pem

    ProxyPass /jupyter/ http://127.0.0.1:8888/jupyter/
    ProxyPassReverse /jupyter/ http://127.0.0.1:8888/jupyter/
</VirtualHost>
```

## 3. Test a kernel and reload

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
```

Open `https://lab.example.test/jupyter/`, authenticate, create a kernel, and run
a cell that prints `Vapache Jupyter test`. Keep the kernel open and reload
Vapache again.

The current WebSocket can close during reload. Reconnect the browser and run a
second cell in the same kernel. A successful `101 Switching Protocols` response
does not prove that the kernel protocol works; confirm that both cells return
their output.

Shut down the test kernel after the check succeeds.

<!--
Deployment contract only; not operator instructions.
--scenario jupyterlab-proxy
Canonical dimensions: `mount=subpath`, `websocket=execute`, `reload=while-open`.
Scenario storage budget: 3072 MiB.
[Scenario](../../tests/deployments/scenarios/jupyterlab-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/jupyterlab-proxy/driver.py)
-->
