# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-25T00:15:06.190221+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| proxy static | 4004 | 2820 | 0.70x | 168.78 | 57.87 |
| <Proxy> deny | 144133 | 184778 | 1.28x | 0.60 | 0.31 |
| <ProxyMatch> allow | 3869 | 3526 | 0.91x | 159.13 | 99.21 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 21.4 ms | 6.3 ms |
| processes after load | 7 | 33 |
| threads after load | 313 | 54 |
| PSS after load | 31.9 MiB | 30.9 MiB |

## Reading the numbers

- 2 scenario(s) were below Apache in this run; see the table (proxy/rewrite/CGI long-tail scenarios are the usual remaining cases).
- The feature-rich conformance configuration adds conditional rules, cache lookups, `.htaccess` candidates, vhost selection and proxy matching to every request; compare these ratios with the static `bench.py` results rather than treating them as a core-server regression.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
