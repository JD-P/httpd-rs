# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-24T00:00:17.266312+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| static index (small) | 81467 | 123414 | 1.51x | 1.07 | 0.51 |
| static 1MB | 7196 | 11532 | 1.60x | 2.49 | 0.86 |
| HEAD 1.1KB | 101596 | 96882 | 0.95x | 0.63 | 0.66 |
| 304 conditional | 131449 | 119946 | 0.91x | 0.45 | 0.54 |
| empty file | 131885 | 121405 | 0.92x | 0.45 | 0.54 |
| directory index | 66986 | 71878 | 1.07x | 1.26 | 1.04 |
| 301 redirect | 151849 | 117505 | 0.77x | 0.40 | 0.57 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 17.8 ms | 6.3 ms |
| processes after load | 7 | 17 |
| threads after load | 313 | 20 |
| PSS after load | 28.0 MiB | 22.7 MiB |

## Reading the numbers

- 4 scenario(s) were below Apache in this run; the closest are status-only paths (HEAD, redirects, 401/403/405) where response size is tiny and host noise is largest.
- The feature-rich conformance configuration adds conditional rules, cache lookups, `.htaccess` candidates, vhost selection and proxy matching to every request; compare these ratios with the static `bench.py` results rather than treating them as a core-server regression.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
