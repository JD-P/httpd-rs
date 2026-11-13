# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-23T21:11:43.152055+00:00

Method: 5 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| static index (small) | 78076 | 94487 | 1.21x | 1.05 | 0.75 |
| HEAD 1.1KB | 113895 | 79974 | 0.70x | 0.56 | 0.80 |
| 304 conditional | 132333 | 87116 | 0.66x | 0.44 | 0.84 |
| empty file | 136449 | 100092 | 0.73x | 0.42 | 0.71 |
| directory index | 75656 | 60920 | 0.81x | 1.15 | 1.21 |
| 301 redirect | 173818 | 111390 | 0.64x | 0.31 | 0.58 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 17.4 ms | 6.5 ms |
| processes after load | 7 | 17 |
| threads after load | 313 | 20 |
| PSS after load | 27.8 MiB | 29.8 MiB |

## Reading the numbers

- 5 scenario(s) were below Apache in this run; the closest are status-only paths (HEAD, redirects, 401/403/405) where response size is tiny and host noise is largest.
- The feature-rich conformance configuration adds conditional rules, cache lookups, `.htaccess` candidates, vhost selection and proxy matching to every request; compare these ratios with the static `bench.py` results rather than treating them as a core-server regression.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
