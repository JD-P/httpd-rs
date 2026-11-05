# Tested application deployments

The real-application harness verifies thirteen deployment patterns: four fixed
nightly cases and nine applications in the stochastic manual population. The
exact generated configuration and logs are retained with every run; these
guides explain the security-relevant differences from a typical Apache or
Nginx installation.

The feature-to-application rationale is maintained in the
[application coverage inventory](coverage.md).

| Application | Vapache mode | Workflows exercised |
|---|---|---|
| Hugo | static | generated routes, custom errors, `.htaccess`, Basic auth, compression, ranges and cache |
| Gitweb + smart Git HTTP | CGI | query strings, `PATH_INFO`, CGI environment, authentication and a real clone |
| WordPress | FastCGI | PHP-FPM Unix socket, install/login, REST, media upload, permalinks, rewrites and static cache |
| Grafana | reverse proxy + WebSocket | subpath redirects, forwarded authority, health API, upgrade and bidirectional frames across reload |
| Gitea (manual sample) | reverse proxy | API state creation followed by authenticated smart-HTTP push and clone |
| Drupal (manual sample) | FastCGI | real installer, shipped `.htaccess`, clean URLs, protected files and immutable PHP source |
| Jenkins (manual sample) | reverse proxy | root/subpath mounts, Basic auth, CSRF crumb/session binding, form POST and job API |
| JupyterLab (manual sample) | reverse proxy + WebSocket | token auth, root/subpath mounts, kernel creation and code execution across reload |
| MinIO (manual sample) | reverse proxy | SigV4 authority binding, signed streaming upload, ranges and object listing |
| Nextcloud (manual sample) | FastCGI + WebDAV | database install, Basic auth forwarding, DAV verbs, large upload, move and download |
| Wagtail Bakery Demo (manual sample) | reverse proxy | Gunicorn worker variants, public API, CSRF-bound admin login and session survival across reload |
| Bugzilla (manual sample) | FastCGI | large Perl application setup, stable worker identity, REST `PATH_INFO`, CSRF-bound login and administrative policy |
| Mastodon (manual sample) | TLS reverse proxy + WebSocket | PostgreSQL/Redis/Puma/Sidekiq composition, bearer API, status fan-out and authenticated streaming across reload |

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

## Drupal with PHP-FPM

Drupal uses the protected Unix-socket and immutable-code model described for
WordPress, with `web/sites/default/files` as its only PHP-writable subtree.
Its upstream `.htaccess` is executed rather than replaced, with four bounded
compatibility adaptations:

- two PCRE negative lookaheads become ordered, bounded rewrite rules;
- `Header append` becomes the equivalent supported `Header add` form;
- `RequestHeader unset Proxy` is removed because Vapache never creates
  `HTTP_PROXY` from the request `Proxy` field;
- `AddEncoding` moves to main configuration, where Vapache supports it.

The adapter fails if those exact upstream lines drift, so a future Drupal
change cannot silently discard policy. The test installs a real profile,
loads a clean URL, rejects `composer.json`, rejects direct `.htaccess` access,
and reloads the server. The FastCGI `SCRIPT_FILENAME` path must exist
identically in Vapache's and PHP-FPM's mount namespaces.

## Jenkins

Jenkins 2.580.2 LTS with JDK 21 is an ordinary HTTP backend on an
internal-only network. Root and `/jenkins/` deployments use matching public
and backend prefixes:

```apache
ProxyPass /jenkins/ http://BACKEND:8080/jenkins/
ProxyPassReverse /jenkins/ http://BACKEND:8080/jenkins/
```

The test authenticates, obtains a CSRF crumb and its bound session cookie,
creates a job by POSTing XML, and reads the authenticated job API after a
reload. Jenkins was selected for the Java slot because its maintained LTS
image has a current immutable amd64 manifest.

## JupyterLab

JupyterLab is configured with the same `base_url` used in both proxy rules.
The workflow creates a kernel through the HTTP API and performs a real Jupyter
wire-protocol execution over WebSocket. A graceful reload deliberately closes
the tunnel owned by the old configuration generation; the test reconnects
under the new grant and proves the existing kernel still executes code. This
is the safe expected behavior, not transparent tunnel migration.

## MinIO

S3 Signature V4 covers the public authority, so this deployment explicitly
uses:

```apache
ProxyPreserveHost On
ProxyPass / http://BACKEND:9000/
ProxyPassReverse / http://BACKEND:9000/
```

Vapache validates the request authority before reconstructing the upstream
header and preserves its non-default port. The test creates a bucket, uploads
an approximately 1 MiB object using AWS's per-chunk signature chain, reloads,
checks a byte range and listing, then removes the object and bucket. Do not
enable `ProxyPreserveHost` for unrelated backends that expect their private
authority.

## Nextcloud with PHP-FPM

Nextcloud requires raw HTTP authentication at its WebDAV front controller.
Apache-compatible forwarding is explicit and directory scoped:

```apache
<Directory "/srv/nextcloud">
    CGIPassAuth On
    Require all granted
</Directory>
```

`CGIPassAuth` defaults off; scope inheritance can turn it off again below this
directory. The hardened layout sets Nextcloud's documented
`config_is_read_only=true`, makes code and `config.php` immutable, leaves only
the data directory writable by PHP-FPM, and denies direct access to `config/`,
`data/`, `lib/`, dot files and command-line entry points. The test performs an
authenticated `MKCOL`, upload, `PROPFIND`, `MOVE`, reload, exact download and
delete against MariaDB-backed Nextcloud.

## Wagtail Bakery Demo with Gunicorn

The Bakery Demo is built from a digest-verified source commit with exact Python
package versions, then runs unprivileged with an immutable root and only its
media directory writable. PostgreSQL is confined to the internal application
network. Django validates the public authority, so the proxy intentionally
uses `ProxyPreserveHost On`; the private container address is never accepted
as an application host. The test reads fixture content through Wagtail's API,
performs a real CSRF-bound admin login, exercises both one- and two-worker
Gunicorn configurations, and proves the authenticated session remains valid
after Vapache reload.

## Bugzilla through generic FastCGI

Bugzilla is built from a digest-verified 5.2 source commit and served by
`fcgiwrap` as `www-data`. The executable application tree is root-owned and
immutable after `checksetup.pl`; only Bugzilla's generated data is writable by
the worker. Vapache's FastCGI stable-path policy binds the Unix socket to UID
33 and permits only the release owner and root along the script path. The
socket is mode `0660`, owned by the backend UID and Vapache's service group;
unrelated local users cannot bypass the front end. Direct reads of Perl
modules, templates and `localconfig` are denied. The test uses the real
two-pass installer, MariaDB, the REST version endpoint through `PATH_INFO`,
Bugzilla's login-request cookie and CSRF token, query/admin pages, and an
authenticated reload.

## Mastodon

Mastodon is the deliberately large operational-composition case. PostgreSQL,
Redis, Puma, Sidekiq and Mastodon's dedicated Node streaming service share an
internal-only container network. Vapache is the only public HTTP path. The two
backends require ordered routes, with the streaming prefix before the general
web route:

```apache
<VirtualHost *:443>
    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem
    ProxyPreserveHost On
    ProxyPass /api/v1/streaming http://STREAMING:4000/api/v1/streaming
    ProxyPassReverse /api/v1/streaming http://STREAMING:4000/api/v1/streaming
    ProxyPass / http://WEB:3000/
    ProxyPassReverse / http://WEB:3000/
</VirtualHost>
```

`LOCAL_DOMAIN` and the preserved public `Host` must agree; do not substitute
an ephemeral private backend address. Mastodon production mode requires HTTPS;
terminate TLS at Vapache so its non-spoofable connection state generates the
correct `X-Forwarded-Proto: https`. Do not accept a client-supplied forwarded
scheme on a plaintext listener. The checked-in cryptographic values and
database password are isolated test fixtures, not deployment defaults. A real
installation must generate independent Rails encryption, OTP, VAPID and
database secrets and retain them across upgrades.

The workflow creates a confirmed local account and scoped bearer token, opens
an authenticated stream, reloads Vapache, reconnects under the new policy
generation, publishes a real status through Puma, and waits for Sidekiq and
Redis to deliver that exact status through the streaming WebSocket. One- and
two-worker Puma layouts plus user and public-local streams are stochastically
sampled. Only the media directory is writable by the application; no
container can see the source checkout.

## Future expansion

The representative application inventory is complete. Add another application
only when it exposes a distinct Vapache boundary rather than duplicating an
implementation language behind ordinary HTTP. CalDAV/CardDAV can deepen the
existing Nextcloud case without another deployment.

