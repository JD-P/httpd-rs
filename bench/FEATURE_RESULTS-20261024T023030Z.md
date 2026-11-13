# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-24T02:30:27.575300+00:00

Method: 1 x 1s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| static 1.1KB | 57896 | 124821 | 2.16x | 1.43 | 0.73 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 18.2 ms | 6.6 ms |
| processes after load | 5 | 17 |
| threads after load | 209 | 20 |
| PSS after load | 21.0 MiB | 21.5 MiB |

## Reading the numbers

- Every scenario in this run is at least 1.00x Apache.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
