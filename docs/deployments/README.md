# Tested application deployments

The real-application harness continuously verifies four deployment patterns.
The exact generated configuration and logs are retained with every CI run;
these guides explain the security-relevant differences from a typical Apache
or Nginx installation.

The feature-to-application rationale is maintained in the
[application coverage inventory](coverage.md).

| Application | Vapache mode | Workflows exercised |
|---|---|---|
| Hugo | static | generated routes, custom errors, `.htaccess`, Basic auth, compression, ranges and cache |
| Gitweb + smart Git HTTP | CGI | query strings, `PATH_INFO`, CGI environment, authentication and a real clone |
| WordPress | FastCGI | PHP-FPM Unix socket, install/login, REST, media upload, permalinks, rewrites and static cache |
| Grafana | reverse proxy + WebSocket | subpath redirects, forwarded authority, health API, upgrade and bidirectional frames across reload |
| Gitea (manual sample) | reverse proxy | API state creation followed by authenticated smart-HTTP push and clone |

## Hugo

The generator runs with no network, a read-only container root, no Linux
capabilities and only the temporary site source mounted. Vapache serves the
generated `public/` tree directly. The canonical case enables
`VapacheCapability AccessFiles On` specifically to test a small `.htaccess`
rewrite/header policy; deployments that keep all policy in the main
configuration should leave that capability disabled.

Static assets are the only cache-enabled URL prefix. Authentication is applied
to the resolved private directory, and the test verifies both the rejection
and authenticated response.

## Gitweb and smart Git HTTP

`gitweb.cgi` and Git's `git-http-backend` are executed through the managed CGI
worker pool. This requires the explicit global gate:

```apache
VapacheCapability Cgi On
```

The executable and repository trees must not be writable by the service
identity. `GITWEB_CONFIG`, `GIT_PROJECT_ROOT` and `GIT_HTTP_EXPORT_ALL` are
fixed configuration values; no request value is converted into an executable
or filesystem root. The integration test renders Gitweb and performs a real
smart-HTTP clone, optionally under Basic authentication.

## WordPress with PHP-FPM

The tested layout uses a protected Unix socket rather than loopback TCP:

```apache
VapacheCapability AccessFiles On
VapacheCapability FastCgi On
VapacheFastCGIStablePath On unix:/run/php/php-fpm.sock 33 33 0 DEPLOY_UID
ProxyPassMatch ^/(.*\.php(/.*)?)$ \
    "unix:/run/php/php-fpm.sock|fcgi://localhost/srv/wordpress/"
```

`DEPLOY_UID` is the trusted release owner, not the web-service or PHP-FPM
identity. PHP source and every ancestor are immutable to PHP-FPM; only
`wp-content/uploads` is writable. PHP execution is explicitly denied in that
writable subtree:

```apache
<Directory "/srv/wordpress/wp-content/uploads">
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</Directory>
```

Consequently, dashboard-driven core/plugin/theme modification is intentionally
not supported by this hardened layout. Update an immutable release tree out of
band, verify it, and atomically deploy it. Media uploads remain functional.
The database has no published host port and is not reachable from clients.

The standard WordPress permalink `.htaccess` works with
`AllowOverride FileInfo`; no unsafe FastCGI pathname capability is enabled.

## Grafana

Grafana listens on a loopback-only port and Vapache owns the public endpoint.
Both root and `/grafana/` subpath deployments are sampled. The subpath form is:

```apache
ProxyPass /grafana/ http://127.0.0.1:3000/
ProxyPassReverse /grafana/ http://127.0.0.1:3000/
```

`GF_SERVER_ROOT_URL` must name the public Vapache URL and
`GF_SERVER_SERVE_FROM_SUB_PATH` must be enabled for the subpath form. Vapache
uses the same route for the `/api/live/ws` upgrade. The test opens a real
Grafana Live WebSocket, reloads Vapache while it is open, and verifies a
bidirectional ping/pong before closing it.

## Gitea

Gitea is part of the stochastic manual population rather than the fixed
nightly quota. It runs as the invoking unprivileged uid with SQLite state in a
scenario bind directory, no SSH listener, and an internal-only container
network. Both root and `/gitea/` mounts are selectable. The workflow creates a
repository through the API, pushes a commit through Vapache's HTTP proxy, then
clones it and checks the resulting content. This covers request bodies and
streaming behavior that a simple health endpoint would miss.

## Planned manual expansion

The next applications should be added for distinct semantics: Bugzilla
(large CGI), Drupal (rich `.htaccess`), Nextcloud (DAV and large uploads),
Wagtail (Python/Gunicorn), Spring PetClinic (Java), JupyterLab (subpaths and
WebSockets), MinIO (signed streaming), and
Zulip or Mastodon (large multi-service deployment). They should join the
stochastic manual population before any are promoted into the fixed nightly
set.

