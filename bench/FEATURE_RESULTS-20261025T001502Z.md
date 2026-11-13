# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-25T00:14:09.667073+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| DirectoryIndex CGI | 2778 | 9780 | 3.52x | 14.51 | 3.28 |
| ErrorDocument CGI | 2899 | 9804 | 3.38x | 13.62 | 3.27 |
| CGI GET | 2529 | 6086 | 2.41x | 14.50 | 5.27 |
| CGI POST | 2272 | 5499 | 2.42x | 7.04 | 2.91 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 17.1 ms | 6.2 ms |
| processes after load | 7 | 33 |
| threads after load | 313 | 36 |
| PSS after load | 30.4 MiB | 31.5 MiB |

## Reading the numbers

- Every scenario in this run is at least 1.00x Apache.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
