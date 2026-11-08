---
doc_type: landing
audience: application-operator
status: draft
---

# Choose a deployment tutorial

Choose the tutorial for your application. If the application is not listed,
choose one that connects to the web server in the same way.

Each tutorial assumes that the application is installed on a Linux VPS. It
shows the application settings, Vapache configuration, checks, and rollback for
one concrete deployment.

The “similar software” column lists applications that connect to the web server
in a similar way. It does not mean that the listed software accepts the same
configuration.

| Tutorial | What the tutorial covers | Tested workflow | Similar software and starting points |
|---|---|---|---|
| [Hugo static site](hugo-static-site.md) | Static files, HTTPS, custom errors, compression, byte ranges, and reload <!-- test modes: `static`, `access`, `compression`, `cache` --> | Build a release; test the home page, custom `404`, Brotli, a byte range, and reload | Jekyll, Eleventy, MkDocs, Docusaurus, Zola |
| [Gitweb and smart Git HTTP](git-cgi.md) | CGI, path information, and request bodies <!-- test modes: `cgi`, `path-info`, `request-body` --> | Browse Gitweb and clone a repository through CGI | cgit, ViewVC, other bounded CGI programs |
| [WordPress with PHP-FPM](wordpress-php-fpm.md) | PHP-FPM, rewrites, cookies, uploads, and a database <!-- test modes: `fastcgi`, `rewrite`, `cookies`, `database` --> | Install, upload media, use pretty URLs and REST, cache assets, and reload | ClassicPress, Joomla, TYPO3, other PHP-FPM content systems |
| [Grafana reverse proxy](grafana-reverse-proxy.md) | Reverse proxying, WebSocket, redirects, and cookies <!-- test modes: `reverse-proxy`, `websocket`, `redirects`, `cookies` --> | Use a subpath, follow public redirects, exchange WebSocket frames, and reload | OpenSearch Dashboards, Kibana, Netdata, other live dashboards |
| [Gitea reverse proxy](gitea-reverse-proxy.md) | Reverse proxying, streamed request bodies, cookies, and Git HTTP <!-- test modes: `reverse-proxy`, `streaming`, `request-body`, `cookies`, `git-smart-http` --> | Create a repository, push, reload, and clone through a subpath | Forgejo, GitLab smart HTTP, other Git forges |
| [Drupal with PHP-FPM](drupal-php-fpm.md) | PHP-FPM, `.htaccess`, rewrites, and cookies <!-- test modes: `fastcgi`, `htaccess`, `rewrite`, `cookies` --> | Install Drupal, execute its adapted access file, protect private files, and reload | Joomla, TYPO3, MediaWiki, other PHP-FPM applications with access files |
| [Jenkins reverse proxy](jenkins-reverse-proxy.md) | Reverse proxying, authentication, forms, and redirects <!-- test modes: `reverse-proxy`, `java`, `authentication`, `forms`, `redirects` --> | Authenticate, obtain a CSRF crumb, create a job, and reload | TeamCity, GoCD, other stateful Java web applications |
| [JupyterLab reverse proxy](jupyterlab-reverse-proxy.md) | Reverse proxying, WebSocket, subpaths, and cookies <!-- test modes: `reverse-proxy`, `websocket`, `subpath`, `cookies` --> | Create a kernel, execute through WebSocket, reload, reconnect, and execute again | code-server, RStudio Server, other interactive WebSocket applications |
| [MinIO reverse proxy](minio-reverse-proxy.md) | Reverse proxying, streamed uploads, signed requests, and byte ranges <!-- test modes: `reverse-proxy`, `streaming`, `signed-requests`, `ranges` --> | Send SigV4 streaming upload, range, list, reload, and delete operations | Ceph Object Gateway, Garage, other S3-compatible services |
| [Nextcloud with PHP-FPM](nextcloud-php-fpm.md) | PHP-FPM, WebDAV, streamed request bodies, and a database <!-- test modes: `fastcgi`, `webdav`, `streaming`, `request-body`, `database` --> | Upload, `PROPFIND`, `MOVE`, reload, download, and delete through WebDAV | ownCloud, other PHP-FPM WebDAV applications |
| [Wagtail with Gunicorn](wagtail-gunicorn.md) | Reverse proxying, cookies, forms, an API, and a database <!-- test modes: `reverse-proxy`, `python`, `cookies`, `csrf`, `api`, `database` --> | Read the API, complete an admin login, retain the session across reload | Django CMS, Mezzanine, other Django and Gunicorn applications |
| [Bugzilla with generic FastCGI](bugzilla-fastcgi.md) | FastCGI, cookies, forms, path information, and a database <!-- test modes: `fastcgi`, `perl`, `cookies`, `csrf`, `path-info`, `database` --> | Run the installer, use REST path info, authenticate, protect source files, and reload | Request Tracker, legacy Perl FastCGI applications |
| [Mastodon with TLS and streaming](mastodon-tls-streaming.md) | TLS, reverse proxying, WebSocket, APIs, and background jobs <!-- test modes: `reverse-proxy`, `websocket`, `tls-termination`, `api`, `database`, `background-jobs` --> | Authenticate, publish through background jobs, receive the event through WebSocket, and reload | Pleroma, Akkoma, Discourse, other multi-service event applications |

## Ask your agent to adapt a tutorial

If the application is not listed, give your coding agent the application and
version, its deployment documentation, the closest tutorial, and the Vapache
configuration from that tutorial.

Ask it to return:

- how the application connects to the web server;
- which tutorial settings can remain unchanged;
- the paths, ports, users, public URL settings, and credentials that must
  change;
- the application operations that need positive and negative tests;
- any behavior that the tutorial does not cover.

## Migration tutorial

The [Debian static-site migration tutorial](migrate-debian-static-site.md)
starts with an existing Apache virtual host. It covers the service switch and
rollback for a site that is already in production.
