# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-23T23:28:20.831071+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| static index (small) | 84819 | 145440 | 1.71x | 0.99 | 0.41 |
| static 1MB | 7949 | 11828 | 1.49x | 2.65 | 0.84 |
| HEAD 1.1KB | 113043 | 121913 | 1.08x | 0.57 | 0.53 |
| 304 conditional | 134561 | 145491 | 1.08x | 0.44 | 0.42 |
| empty file | 136601 | 159176 | 1.17x | 0.42 | 0.37 |
| directory index | 78336 | 101611 | 1.30x | 1.09 | 0.65 |
| 301 redirect | 183901 | 187158 | 1.02x | 0.30 | 0.30 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 17.8 ms | 6.3 ms |
| processes after load | 7 | 17 |
| threads after load | 313 | 20 |
| PSS after load | 27.7 MiB | 22.9 MiB |

## Reading the numbers

- Every scenario in this run is at least 1.00x Apache.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
