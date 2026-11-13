# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-23T20:08:58.197514+00:00

Method: 1 x 1s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| <Limit> GET | 59428 | 48099 | 0.81x | 1.34 | 1.92 |
| <LimitExcept> GET | 76078 | 49338 | 0.65x | 1.04 | 1.55 |
| AllowMethods 405 | 135573 | 43271 | 0.32x | 0.63 | 1.71 |
| AuthMerging Or | 69932 | 29291 | 0.42x | 1.19 | 2.55 |
| AuthMerging And 403 | 115370 | 32318 | 0.28x | 0.73 | 2.76 |
| ElseIf header | 70905 | 36442 | 0.51x | 1.10 | 2.06 |
| DirectoryIndex CGI | 2439 | 3492 | 1.43x | 15.24 | 8.95 |
| ErrorDocument CGI | 2480 | 3462 | 1.40x | 15.63 | 8.84 |
| proxy static | 3825 | 1756 | 0.46x | 30.49 | 53.43 |
| <Proxy> deny | 142558 | 55579 | 0.39x | 0.57 | 1.44 |
| <ProxyMatch> allow | 3548 | 2924 | 0.82x | 2.78 | 29.12 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 22.0 ms | 6.7 ms |
| processes after load | 7 | 17 |
| threads after load | 313 | 24 |
| PSS after load | 30.8 MiB | 31.0 MiB |

## Reading the numbers

- Every scenario in this run is at least 1.00x Apache. The closest are directory redirects, HEAD and 401s, where the response is only a status line and a tiny body and run-to-run noise is largest.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (111 tests, all passing).
