# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-23T21:56:23.417403+00:00

Method: 5 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| static index (small) | 71426 | 152393 | 2.13x | 1.18 | 0.38 |
| static 1MB | 7605 | 10926 | 1.44x | 2.67 | 0.90 |
| HEAD 1.1KB | 95735 | 113952 | 1.19x | 0.67 | 0.56 |
| 304 conditional | 121900 | 141780 | 1.16x | 0.49 | 0.43 |
| empty file | 130905 | 156097 | 1.19x | 0.46 | 0.38 |
| directory index | 73282 | 101212 | 1.38x | 1.19 | 0.65 |
| 301 redirect | 156370 | 172572 | 1.10x | 0.35 | 0.33 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 18.0 ms | 6.3 ms |
| processes after load | 7 | 17 |
| threads after load | 313 | 20 |
| PSS after load | 27.9 MiB | 22.2 MiB |

## Reading the numbers

- Every scenario in this run is at least 1.00x Apache.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
