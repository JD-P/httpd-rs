# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-28T16:29:53.134349+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. HTTP/2 uses 64 clients x 16 streams; the 1 MB case uses 16 x 4 and CGI uses 16-32 clients.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| static index (small) | 84402 | 145071 | 1.72x | 1.01 | 0.38 |
| static 1.1KB | 84548 | 141477 | 1.67x | 0.97 | 0.39 |
| static 10KB | 79695 | 125587 | 1.58x | 1.00 | 0.43 |
| static 1MB | 7432 | 10719 | 1.44x | 2.67 | 0.92 |
| HEAD 1.1KB | 92085 | 103409 | 1.12x | 0.69 | 0.62 |
| 304 conditional | 118657 | 127160 | 1.07x | 0.49 | 0.46 |
| 206 range | 74152 | 135648 | 1.83x | 1.20 | 0.41 |
| empty file | 118177 | 154970 | 1.31x | 0.50 | 0.35 |
| directory index | 77130 | 105824 | 1.37x | 1.10 | 0.54 |
| autoindex | 72462 | 79973 | 1.10x | 0.86 | 0.74 |
| directory redirect | 140085 | 141566 | 1.01x | 0.41 | 0.39 |
| 301 redirect | 166322 | 226958 | 1.36x | 0.33 | 0.22 |
| alias | 82288 | 126391 | 1.54x | 1.00 | 0.45 |
| custom 404 | 67668 | 103369 | 1.53x | 1.33 | 0.56 |
| MIME AddType | 85264 | 133244 | 1.56x | 0.96 | 0.43 |
| access allow (IP) | 74132 | 138576 | 1.87x | 1.09 | 0.40 |
| access deny (IP) | 131827 | 190394 | 1.44x | 0.70 | 0.31 |
| <Limit> GET | 67191 | 127677 | 1.90x | 1.25 | 0.45 |
| <LimitExcept> GET | 81002 | 140527 | 1.73x | 1.04 | 0.39 |
| Satisfy Any | 82501 | 140041 | 1.70x | 1.04 | 0.40 |
| Satisfy All 403 | 136271 | 207238 | 1.52x | 0.65 | 0.28 |
| AllowMethods 405 | 133000 | 197808 | 1.49x | 0.72 | 0.27 |
| AuthMerging Or | 71351 | 124422 | 1.74x | 1.14 | 0.45 |
| AuthMerging And 403 | 118990 | 164985 | 1.39x | 0.80 | 0.32 |
| ElseIf header | 72769 | 131326 | 1.80x | 1.14 | 0.42 |
| DirectoryIndex CGI | 2653 | 8051 | 3.03x | 15.40 | 3.98 |
| ErrorDocument CGI | 2523 | 9273 | 3.67x | 15.30 | 3.46 |
| Basic auth 200 | 67866 | 104445 | 1.54x | 1.24 | 0.57 |
| Basic auth 401 | 141170 | 206845 | 1.47x | 0.41 | 0.25 |
| proxy static | 3314 | 3013 | 0.91x | 167.27 | 127.93 |
| <Proxy> deny | 124651 | 175280 | 1.41x | 0.69 | 0.31 |
| <ProxyMatch> allow | 3615 | 3325 | 0.92x | 131.26 | 108.38 |
| rewrite (server) | 74702 | 101484 | 1.36x | 1.18 | 0.59 |
| rewrite (.htaccess) | 56321 | 53740 | 0.95x | 1.49 | 1.27 |
| Header (.htaccess) | 72376 | 76312 | 1.05x | 1.17 | 0.84 |
| name-based vhost | 71319 | 100565 | 1.41x | 1.25 | 0.58 |
| CGI GET | 2064 | 5530 | 2.68x | 16.68 | 5.79 |
| CGI POST | 2063 | 5302 | 2.57x | 7.76 | 3.02 |
| HTTPS/1.1 static | 63684 | 85651 | 1.34x | 0.90 | 0.73 |
| HTTP/2 static | 47350 | 188824 | 3.99x | 21.52 | 5.17 |
| HTTP/2 10KB | 42272 | 129358 | 3.06x | 24.08 | 5.86 |
| HTTP/2 1MB | 4880 | 4372 | 0.90x | 10.80 | 10.40 |
| HTTP/2 range | 47214 | 187704 | 3.98x | 21.65 | 5.13 |
| HTTP/2 Basic auth | 38517 | 144360 | 3.75x | 26.54 | 6.93 |
| HTTP/2 vhost (SNI) | 40968 | 125592 | 3.07x | 24.93 | 8.04 |
| HTTP/2 CGI GET | 1026 | 5580 | 5.44x | 252.21 | 45.88 |
| HTTP/2 CGI POST | 921 | 5110 | 5.55x | 69.92 | 12.51 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 18.5 ms | 6.5 ms |
| processes after load | 7 | 33 |
| threads after load | 385 | 36 |
| PSS after load | 132.2 MiB | 107.0 MiB |

## Reading the numbers

- 4 scenario(s) were below Apache in this run; see the table (proxy/rewrite/CGI long-tail scenarios are the usual remaining cases).
- The feature-rich conformance configuration adds conditional rules, cache lookups, `.htaccess` candidates, vhost selection and proxy matching to every request; compare these ratios with the static `bench.py` results rather than treating them as a core-server regression.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses blocking-pool positional reads and bounded buffer reuse so one stream does not stall the other streams on a connection. mmap is used only when the verified ownership/mode predicate permits it. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
