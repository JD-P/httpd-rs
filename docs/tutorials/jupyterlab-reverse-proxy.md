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

You will install JupyterLab in a dedicated Python environment, create its
systemd service, bind it to loopback, add the Vapache route, execute code in a
kernel, reload Vapache, reconnect, and use the same kernel.

## Before you start

Complete [Prepare a Debian VPS for a Vapache
tutorial](prepare-debian-vps.md). Point `lab.example.test` at the VPS and open
TCP ports 80 and 443 in the provider firewall.

## 1. Install JupyterLab

```console
$ sudo apt install python3-venv
$ sudo adduser --system --group --home /srv/jupyter jupyter
$ sudo python3 -m venv /opt/jupyterlab
$ sudo /opt/jupyterlab/bin/pip install --upgrade pip jupyterlab
$ sudo -u jupyter /opt/jupyterlab/bin/jupyter server password
$ sudo certbot certonly --standalone --domain lab.example.test
```

Enter the password that administrators will use at the public JupyterLab login
page. The password command stores a hash below `/srv/jupyter`; it does not store
the entered password as plain text.

## 2. Configure the JupyterLab service

Create the system configuration directory:

```console
$ sudo install -d -o root -g root -m 0755 /etc/jupyter
```

Create `/etc/jupyter/jupyter_server_config.py`:

```python
c.ServerApp.ip = '127.0.0.1'
c.ServerApp.port = 8888
c.ServerApp.base_url = '/jupyter/'
c.ServerApp.open_browser = False
c.ServerApp.trust_xheaders = True
```

Create `/etc/systemd/system/jupyterlab.service`:

```systemd
[Unit]
Description=JupyterLab
After=network.target

[Service]
User=jupyter
Group=jupyter
WorkingDirectory=/srv/jupyter
ExecStart=/opt/jupyterlab/bin/jupyter lab --config=/etc/jupyter/jupyter_server_config.py
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Start JupyterLab and test its private endpoint:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now jupyterlab.service
$ curl -I http://127.0.0.1:8888/jupyter/
```

## 3. Configure Vapache

Create `/etc/apache2/sites-available/jupyterlab.conf`:

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

Enable the virtual host, test the configuration, and start Vapache:

```console
$ sudo a2ensite jupyterlab.conf
$ sudo vapachectl configtest
$ sudo systemctl enable --now vapache.service
```

## 4. Test a kernel and reload

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
Documentation case: `mount=subpath`, `websocket=execute`, `reload=while-open`.
Scenario storage budget: 3072 MiB.
[Scenario](../../tests/deployments/scenarios/jupyterlab-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/jupyterlab-proxy/driver.py)
-->
