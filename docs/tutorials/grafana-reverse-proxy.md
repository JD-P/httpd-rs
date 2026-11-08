---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-GRAFANA-001
scenario: grafana-proxy
---

# Run the tested Grafana reverse-proxy deployment

This tutorial runs Grafana below `/grafana/` and sends HTTP and WebSocket
traffic through Vapache. Grafana generates public redirects for the Vapache
authority, not for its private backend address.

## What you will do

You will run the canonical `grafana-proxy` deployment, verify the health and
redirect behavior, exchange a WebSocket message, reload Vapache, and reconnect
under the new configuration generation.

## Before you start

You need Docker, 1024 MiB for the scenario, the Docker safety reserve, and root
or passwordless `sudo`.

## 1. Build and run the deployment

```console
$ cargo build --locked --release -p vapached
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario grafana-proxy \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `mount=subpath`, `reload=after-start`, and
`websocket=message`.

## 2. Verify the result

The final status must be `passed`. The workflow checks `/grafana/api/health`,
follows any public redirect without exposing the backend port, opens Grafana
Live, reloads Vapache, reconnects the tunnel, exchanges a ping and pong, and
checks health again.

## 3. Inspect the tested configuration

```console
$ find deployment-results -path '*grafana-proxy-*' -name vapache.conf -print
```

The Vapache route and Grafana `root_url` use the same `/grafana/` prefix. The
same route carries the `/api/live/ws` upgrade. Vapache closes a tunnel that
belongs to the retired configuration generation; the client reconnects.

## 4. Adapt the pattern

Set the application's public URL before you configure `ProxyPass`. Match the
public and backend prefix rules. Verify redirects and one bidirectional
WebSocket exchange. Do not use a health response as the only WebSocket test.

## Clean up

The harness removes Grafana and its private network. It retains the exact
configuration, plan, summary, and logs.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/grafana-proxy/scenario.toml)
and [driver](../../tests/deployments/scenarios/grafana-proxy/driver.py).
