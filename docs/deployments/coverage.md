# Application coverage inventory

This inventory selects applications by the server behavior visible at the
Vapache boundary. An implementation language behind ordinary HTTP does not
create a distinct Vapache path; body framing, rewrites, upgrades, subpath
routing and backend lifetime do.

| Vapache surface | Real-application coverage | Remaining role of focused suites |
|---|---|---|
| Static path resolution and directory indexes | Hugo generated pages and assets | Alias/symlink edge matrices remain in conformance tests |
| Custom errors, ranges and validators | Hugo 404 and binary range workflow | Full conditional/range combinations remain differential |
| `.htaccess`, rewrite and headers | Hugo policy; WordPress permalinks; Drupal's adapted upstream policy | Malformed and nested scope semantics remain fuzz/differential |
| Basic authentication | Hugo private tree; Git CGI routes | Provider/hash and merge matrices remain focused tests |
| Compression and static cache | Hugo assets; optional WordPress assets | Encoding/range/cache-key matrices remain focused tests |
| CGI environment, query and `PATH_INFO` | Gitweb; Bugzilla REST through generic FastCGI | Injection and descriptor invariants remain adversarial tests |
| CGI request/response body framing | Real smart-HTTP clone through `git-http-backend` | Malformed CGI output remains parser fuzzing |
| FastCGI identity and Unix transport | WordPress, Drupal and Nextcloud/PHP-FPM; Bugzilla/fcgiwrap with stable-path policy | Record corruption and race injection remain focused tests |
| FastCGI rewrites, cookies and auth state | WordPress install/login/REST; Drupal install/clean URLs; Nextcloud WebDAV auth; Bugzilla login/admin | Parameter-level matrices remain conformance tests |
| Writable dynamic content | WordPress media, Drupal files and Nextcloud data with PHP denied or code immutable around them | Spool exhaustion remains resource testing |
| WebDAV verbs and large request bodies | Nextcloud `MKCOL`/`PROPFIND`/`MOVE`, upload and exact download | Full CalDAV/CardDAV method matrices remain focused compatibility work |
| Ordinary HTTP reverse proxy | Grafana, Gitea, Jenkins, JupyterLab, MinIO, Wagtail/Gunicorn and Mastodon/Puma | Malicious backend framing remains adversarial/fuzz testing |
| Proxy subpath and redirect rewriting | Grafana `/grafana/`; Gitea `/gitea/`; Jenkins and Jupyter root/subpath pairs | Regex/capture route order remains differential |
| Proxy request and response streaming | Gitea smart HTTP; Jenkins form body; MinIO signed object transfer | Slow-peer resource accounting remains soak/fault testing |
| Preserved public authority | MinIO SigV4 with `ProxyPreserveHost On` | Invalid/ambiguous authority matrices remain protocol tests |
| WebSocket handshake and bidirectional traffic | Grafana Live; Jupyter kernel execution; authenticated Mastodon status streaming | Malformed frames and slow tunnels remain protocol/soak tests |
| Application-required TLS termination | Mastodon production HTTPS and WSS through a short-lived test certificate | SNI/mTLS/OCSP and protocol matrices remain focused TLS tests |
| Graceful reload with active ownership | Every nightly scenario; Grafana reloads an open WebSocket | Generation race schedules remain deterministic fault tests |
| Multi-service job and event fan-out | Mastodon API through Puma to Sidekiq/Redis and its separate streaming service | Broker failure schedules remain focused fault tests |
| Apache-relative application performance | Optional alternating Apache/Vapache workloads | Microbenchmarks continue isolating front-end overhead |

Several surfaces should not be forced into an application merely to claim
coverage. TLS/SNI/mTLS/OCSP, HTTP/2 framing, Certbot, hostile backend output,
balancer member failover, cache poisoning and resource exhaustion have more
precise existing harnesses. Application topology overlays can later add
HTTPS upstreams and replicated backends once they provide a distinct workflow
rather than duplicating those tests.

The representative application slots are complete. CalDAV/CardDAV extensions
can deepen the existing Nextcloud case without adding another application.

