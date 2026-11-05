# PHP-FPM and Gunicorn application benchmark


Generated: 2026-11-05T00:50:49.130472+00:00


Method: 5 x 3s samples per server after warm-up; PHP-FPM over a Unix socket, Gunicorn with 8 sync workers behind the HTTP proxy; access logs disabled.


| scenario | apache req/s | vapache req/s | ratio | apache mean ms | vapache mean ms | apache p99 ms | vapache p99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| PHP-FPM /index.php | 17424 | 11258 | 0.65x | 0.47 | 0.71 | 1.60 | 1.77 |

## Reading the numbers

- Both handlers are deliberately trivial; this isolates the front-end/FastCGI/proxy hop rather than application work.
- PHP-FPM uses a Unix socket and is the production-shaped PHP path. Native `php-cgi` is not used here.
- Vapache's PHP result keeps its stable-path ownership, writeability, ACL, endpoint-inode and peer-credential checks enabled; Apache does not perform an equivalent per-request proof.
- Gunicorn uses eight default sync workers; vapache intentionally does not pool backend connections without strict response-framing checks. A real WSGI request with application latency will spend most of its time in the app, not this hop.
- Run-to-run variance is material on a shared host; the ratios are more useful than absolute req/s.
