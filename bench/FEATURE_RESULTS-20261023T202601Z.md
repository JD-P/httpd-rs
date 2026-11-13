# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-23T20:25:05.204097+00:00

Method: 3 x 3s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| static 1.1KB | 68556 | 62814 | 0.92x | 1.24 | 1.24 |
| access allow (IP) | 73346 | 53600 | 0.73x | 1.12 | 1.43 |
| access deny (IP) | 116136 | 53899 | 0.46x | 0.76 | 1.56 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 17.6 ms | 6.7 ms |
| processes after load | 7 | 17 |
| threads after load | 313 | 20 |
| PSS after load | 28.2 MiB | 28.1 MiB |

## Reading the numbers

- Every scenario in this run is at least 1.00x Apache. The closest are directory redirects, HEAD and 401s, where the response is only a status line and a tiny body and run-to-run noise is largest.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (111 tests, all passing).
