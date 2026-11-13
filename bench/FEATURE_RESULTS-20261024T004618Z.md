# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-24T00:44:47.727947+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| static index (small) | 74556 | 151246 | 2.03x | 1.13 | 0.39 |
| static 1MB | 7716 | 12753 | 1.65x | 2.55 | 0.80 |
| HEAD 1.1KB | 101839 | 124432 | 1.22x | 0.63 | 0.51 |
| 304 conditional | 129705 | 167536 | 1.29x | 0.46 | 0.34 |
| empty file | 132646 | 188011 | 1.42x | 0.44 | 0.28 |
| directory index | 75916 | 122360 | 1.61x | 1.11 | 0.45 |
| 301 redirect | 175705 | 205763 | 1.17x | 0.33 | 0.26 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 17.9 ms | 6.4 ms |
| processes after load | 7 | 17 |
| threads after load | 313 | 20 |
| PSS after load | 27.9 MiB | 22.3 MiB |

## Reading the numbers

- Every scenario in this run is at least 1.00x Apache.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
