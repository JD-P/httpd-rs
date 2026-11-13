# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-24T22:20:46.756928+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| alias | 65441 | 120289 | 1.84x | 1.33 | 0.47 |
| MIME AddType | 74158 | 135177 | 1.82x | 1.16 | 0.42 |
| access allow (IP) | 70774 | 123337 | 1.74x | 1.24 | 0.48 |
| access deny (IP) | 109642 | 168274 | 1.53x | 0.86 | 0.33 |
| <Limit> GET | 70953 | 113041 | 1.59x | 1.26 | 0.52 |
| <LimitExcept> GET | 71495 | 120843 | 1.69x | 1.18 | 0.48 |
| Satisfy Any | 65677 | 109398 | 1.67x | 1.29 | 0.52 |
| Satisfy All 403 | 119513 | 184020 | 1.54x | 0.86 | 0.30 |
| AllowMethods 405 | 116407 | 180918 | 1.55x | 0.85 | 0.30 |
| AuthMerging Or | 77900 | 129150 | 1.66x | 1.08 | 0.43 |
| AuthMerging And 403 | 125481 | 174771 | 1.39x | 0.82 | 0.32 |
| ElseIf header | 71052 | 114817 | 1.62x | 1.26 | 0.51 |
| rewrite (server) | 71419 | 97640 | 1.37x | 1.23 | 0.60 |
| rewrite (.htaccess) | 53763 | 36071 | 0.67x | 1.67 | 2.30 |
| Header (.htaccess) | 62835 | 60041 | 0.96x | 1.45 | 1.13 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 18.9 ms | 6.8 ms |
| processes after load | 7 | 17 |
| threads after load | 313 | 20 |
| PSS after load | 28.6 MiB | 26.7 MiB |

## Reading the numbers

- 2 scenario(s) were below Apache in this run; see the table (proxy/rewrite/CGI long-tail scenarios are the usual remaining cases).
- The feature-rich conformance configuration adds conditional rules, cache lookups, `.htaccess` candidates, vhost selection and proxy matching to every request; compare these ratios with the static `bench.py` results rather than treating them as a core-server regression.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses mmap-backed bodies and blocking-pool reads so one stream does not stall the other streams on a connection. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
