# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-24T01:17:21.723133+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| static index (small) | 83354 | 156129 | 1.87x | 0.99 | 0.36 |
| static 1MB | 7849 | 11788 | 1.50x | 2.65 | 0.85 |
| HEAD 1.1KB | 113343 | 125573 | 1.11x | 0.56 | 0.51 |
| 304 conditional | 131677 | 169206 | 1.29x | 0.44 | 0.31 |
| empty file | 133811 | 188243 | 1.41x | 0.45 | 0.29 |
| directory index | 72780 | 124387 | 1.71x | 1.17 | 0.45 |
| 301 redirect | 178802 | 212078 | 1.19x | 0.32 | 0.25 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 18.2 ms | 6.7 ms |
| processes after load | 7 | 17 |
| threads after load | 313 | 20 |
| PSS after load | 27.8 MiB | 22.2 MiB |

## Reading the numbers

- Every scenario in this run is at least 1.00x Apache.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
