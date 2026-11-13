# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-23T21:22:06.666060+00:00

Method: 5 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| static index (small) | 81483 | 113036 | 1.39x | 1.06 | 0.59 |
| HEAD 1.1KB | 108460 | 92635 | 0.85x | 0.59 | 0.69 |
| 304 conditional | 129035 | 111830 | 0.87x | 0.46 | 0.61 |
| empty file | 125432 | 108521 | 0.87x | 0.49 | 0.63 |
| directory index | 71233 | 67880 | 0.95x | 1.25 | 1.10 |
| 301 redirect | 169036 | 160081 | 0.95x | 0.35 | 0.37 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 18.6 ms | 6.4 ms |
| processes after load | 7 | 17 |
| threads after load | 313 | 20 |
| PSS after load | 27.7 MiB | 29.2 MiB |

## Reading the numbers

- 5 scenario(s) were below Apache in this run; the closest are status-only paths (HEAD, redirects, 401/403/405) where response size is tiny and host noise is largest.
- The feature-rich conformance configuration adds conditional rules, cache lookups, `.htaccess` candidates, vhost selection and proxy matching to every request; compare these ratios with the static `bench.py` results rather than treating them as a core-server regression.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
