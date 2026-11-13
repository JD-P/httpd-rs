# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-24T00:40:09.036197+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| static index (small) | 81736 | 125025 | 1.53x | 1.05 | 0.56 |
| static 1MB | 7631 | 12837 | 1.68x | 2.49 | 0.79 |
| HEAD 1.1KB | 101802 | 95660 | 0.94x | 0.63 | 0.67 |
| 304 conditional | 117278 | 112172 | 0.96x | 0.50 | 0.60 |
| empty file | 119714 | 136507 | 1.14x | 0.50 | 0.50 |
| directory index | 70657 | 67890 | 0.96x | 1.15 | 1.06 |
| 301 redirect | 158987 | 126074 | 0.79x | 0.36 | 0.54 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 18.0 ms | 4.0 ms |
| processes after load | 7 | 1 |
| threads after load | 313 | 1 |
| PSS after load | 28.0 MiB | 0.0 MiB |

## Reading the numbers

- 4 scenario(s) were below Apache in this run; the closest are status-only paths (HEAD, redirects, 401/403/405) where response size is tiny and host noise is largest.
- The feature-rich conformance configuration adds conditional rules, cache lookups, `.htaccess` candidates, vhost selection and proxy matching to every request; compare these ratios with the static `bench.py` results rather than treating them as a core-server regression.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
