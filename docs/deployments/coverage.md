# Application coverage inventory

This inventory selects applications by the server behavior visible at the
Vapache boundary. An implementation language behind ordinary HTTP does not
create a distinct Vapache path; body framing, rewrites, upgrades, subpath
routing and backend lifetime do.

| Vapache surface | Real-application coverage | Remaining role of focused suites |
|---|---|---|
| Static path resolution and directory indexes | Hugo generated pages and assets | Alias/symlink edge matrices remain in conformance tests |
| Custom errors, ranges and validators | Hugo 404 and binary range workflow | Full conditional/range combinations remain differential |
| `.htaccess`, rewrite and headers | Hugo policy; WordPress permalinks | Malformed and nested scope semantics remain fuzz/differential |
| Basic authentication | Hugo private tree; Git CGI routes | Provider/hash and merge matrices remain focused tests |
| Compression and static cache | Hugo assets; optional WordPress assets | Encoding/range/cache-key matrices remain focused tests |
| CGI environment, query and `PATH_INFO` | Gitweb | Injection and descriptor invariants remain adversarial tests |
| CGI request/response body framing | Real smart-HTTP clone through `git-http-backend` | Malformed CGI output remains parser fuzzing |
| FastCGI identity and Unix transport | WordPress/PHP-FPM with stable-path policy | Record corruption and race injection remain focused tests |
| FastCGI rewrites, cookies and auth state | WordPress install/login/REST/permalinks | Parameter-level matrices remain conformance tests |
| Writable dynamic content | WordPress media upload with PHP denied in uploads | Large spool and exhaustion behavior remains resource testing |
| Ordinary HTTP reverse proxy | Grafana and Gitea | Malicious backend framing remains adversarial/fuzz testing |
| Proxy subpath and redirect rewriting | Grafana `/grafana/`; Gitea `/gitea/` | Regex/capture route order remains differential |
| Proxy request and response streaming | Gitea API, authenticated Git push and clone | Slow-peer resource accounting remains soak/fault testing |
| WebSocket handshake and bidirectional traffic | Grafana Live handshake and ping/pong | Malformed frames and slow tunnels remain protocol/soak tests |
| Graceful reload with active ownership | Every nightly scenario; Grafana reloads an open WebSocket | Generation race schedules remain deterministic fault tests |
| Apache-relative application performance | Optional alternating Apache/Vapache workloads | Microbenchmarks continue isolating front-end overhead |

Several surfaces should not be forced into an application merely to claim
coverage. TLS/SNI/mTLS/OCSP, HTTP/2 framing, Certbot, hostile backend output,
balancer member failover, cache poisoning and resource exhaustion have more
precise existing harnesses. Application topology overlays can later add
HTTPS upstreams and replicated backends once they provide a distinct workflow
rather than duplicating those tests.

The next manual applications are prioritized by missing behavior: Nextcloud
for DAV and large/chunked uploads, Bugzilla for a larger CGI codebase,
JupyterLab for subpath WebSockets, MinIO for signed streaming requests, and a
multi-service Zulip or Mastodon deployment for operational/configuration
composition.

