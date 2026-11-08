---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-JUPYTERLAB-001
scenario: jupyterlab-proxy
---

# Run the tested JupyterLab reverse-proxy deployment

This tutorial runs JupyterLab below `/jupyter/`. It sends the HTTP API and the
kernel WebSocket protocol through Vapache.

## What you will do

You will run the canonical `jupyterlab-proxy` deployment, create a kernel,
execute code over WebSocket, reload Vapache while the tunnel is open, reconnect,
and execute through the same kernel again.

## Before you start

You need Docker, 3072 MiB for the scenario, the Docker safety reserve, and root
or passwordless `sudo`.

## 1. Build and run the deployment

```console
$ cargo build --locked --release -p vapached
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario jupyterlab-proxy \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `mount=subpath`, `websocket=execute`, and
`reload=while-open`.

## 2. Verify the result

The final status must be `passed`. The workflow authenticates to the status API,
opens JupyterLab, creates a kernel, executes a marker over the Jupyter wire
protocol, reloads Vapache, reconnects, executes again, and deletes the kernel.

## 3. Inspect the tested configuration

```console
$ find deployment-results -path '*jupyterlab-proxy-*' -name vapache.conf -print
```

JupyterLab and both proxy directives use the same base URL. Reload retires the
old WebSocket grant and closes that tunnel. The kernel remains in the backend,
so the client can reconnect under the new configuration generation.

## 4. Adapt the pattern

Set the Jupyter base URL before startup. Route the same prefix for HTTP and
WebSocket traffic. Verify a real kernel execution, not only a WebSocket `101`
response. Make the client reconnect after a Vapache reload.

## Clean up

The harness deletes the kernel and removes JupyterLab and its private network.
It retains the tested configuration and logs.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/jupyterlab-proxy/scenario.toml)
and [driver](../../tests/deployments/scenarios/jupyterlab-proxy/driver.py).
