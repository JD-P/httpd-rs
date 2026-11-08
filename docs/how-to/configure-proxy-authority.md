---
doc_type: how-to
audience: application-operator
status: draft
contracts: DOC-HOWTO-PROXY-AUTHORITY-001
---

# Configure the public URL and forwarded headers for a reverse proxy

Use this procedure when a backend generates public URLs, validates the `Host`
header, verifies signed requests, or accepts WebSocket upgrades. Automated
proxy tests and application deployment tests exercise this procedure.

## Prerequisites

Bind the backend to a private address or protected Unix socket. Record the
application's configured public URL and trusted-proxy settings. Keep a direct
backend health check that does not depend on the public proxy route.

## 1. Record the public URL and backend endpoint

Record the public URL and the backend endpoint. For example:

```text
Public URL:       https://app.example.test/
Backend endpoint: http://127.0.0.1:8000/
```

Configure the application with the public scheme, host, port, and path prefix.
Do not depend on request headers as the only source of the application's public
URL when the application provides an explicit setting.

## 2. Select the upstream `Host` policy

Use this table:

| Policy | Upstream `Host` | Use when |
|---|---|---|
| Default | Backend host and port | The backend accepts its private endpoint identity |
| `ProxyPreserveHost On` | Validated public request host and port | The backend validates the public host or includes it in signatures |

Example:

```apache
<VirtualHost *:443>
    ServerName app.example.test
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/
</VirtualHost>
```

Set `ProxyPreserveHost On` only in the virtual host that needs it.

## 3. Use Vapache forwarding headers

Vapache removes client-supplied `Forwarded`, `X-Forwarded-For`,
`X-Forwarded-Proto`, and `X-Forwarded-Host` fields. It then emits:

| Field | Vapache source |
|---|---|
| `X-Forwarded-For` | Client IP address |
| `X-Forwarded-Proto` | Actual HTTP or TLS state |
| `X-Forwarded-Host` | Validated public request host |

Configure the backend to trust these fields only from the Vapache proxy
address. Do not use `RequestHeader` to construct a second forwarded-header
chain. Vapache rejects that unsupported request-mutation policy.

## 4. Ask your agent to find the application settings

Give your coding agent the application name and version, its proxy deployment
documentation, the public URL, the private backend endpoint, and the Vapache
virtual host.

Ask the agent to return:

- the exact application setting for its public URL and path prefix;
- the exact trusted-proxy setting;
- whether the application needs `ProxyPreserveHost On`;
- how the application handles `X-Forwarded-For`, `X-Forwarded-Proto`, and
  `X-Forwarded-Host`;
- any WebSocket route that must appear before the catch-all proxy route;
- tests for redirects, login callbacks, signed requests, uploads, and
  WebSocket reconnection that the application uses.

The configuration must not trust forwarded fields from a public client.

## 5. Test HTTP and WebSocket routes

Run:

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ curl --fail --show-error --head https://app.example.test/
```

Confirm that redirects use the public URL. Test login callbacks, absolute
links, signed downloads, large uploads, and WebSocket connections that the
application uses.

For a subpath deployment, configure the application's public path prefix.
Check a redirect from within the prefix and a request outside the prefix.
Order specific proxy routes before a catch-all route.

If the verification fails, restore the previous proxy directives and reload
Vapache. Keep the backend on its private endpoint while you correct its public
URL or trusted-proxy configuration.

## Evidence

The [conformance suite](../../tests/conformance.py) checks proxy framing,
header filtering, authority, redirects, TLS, and WebSocket behavior. The
canonical [Wagtail](../tutorials/wagtail-gunicorn.md),
[MinIO](../tutorials/minio-reverse-proxy.md), and
[Mastodon](../tutorials/mastodon-tls-streaming.md) deployments exercise public
authority, signed requests, TLS termination, and streaming connections.
