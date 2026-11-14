# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-11-14T14:21:25.410690+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2 with four load-generator threads. Loopback concurrency is capped at eight connections; dynamic-backend cohorts use four outstanding requests with a one-second retirement interval, and HTTP/2 cohorts stay within the 64-stream per-client admission budget. Thus the run measures serving rather than intentional overload rejection. Autoindex is sampled as 60-request bursts aligned to fresh one-second expensive-operation windows.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| static index (small) | 27280 | 22911 | 0.84x | 0.40 | 0.36 |
| static 1.1KB | 25336 | 24019 | 0.95x | 0.45 | 0.33 |
| static 10KB | 25221 | 23569 | 0.93x | 0.41 | 0.39 |
| static 1MB | 5737 | 8870 | 1.55x | 1.57 | 0.86 |
| HEAD 1.1KB | 34616 | 24882 | 0.72x | 0.23 | 0.32 |
| 304 conditional | 37108 | 25606 | 0.69x | 0.23 | 0.32 |
| 206 range | 23748 | 24103 | 1.01x | 0.66 | 0.34 |
| empty file | 38437 | 26949 | 0.70x | 0.21 | 0.39 |
| directory index | 25105 | 18353 | 0.73x | 0.47 | 0.44 |
| autoindex | 13333 | 7816 | 0.59x | 0.60 | 1.02 |
| directory redirect | 43823 | 23765 | 0.54x | 0.19 | 0.34 |
| 301 redirect | 58596 | 46370 | 0.79x | 0.14 | 0.17 |
| alias | 28457 | 23526 | 0.83x | 0.38 | 0.34 |
| custom 404 | 24525 | 16134 | 0.66x | 0.52 | 0.50 |
| MIME AddType | 25749 | 24659 | 0.96x | 0.44 | 0.33 |
| access allow (IP) | 25507 | 24356 | 0.95x | 0.44 | 0.33 |
| access deny (IP) | 40457 | 31625 | 0.78x | 0.21 | 0.27 |
| <Limit> GET | 26418 | 22958 | 0.87x | 0.44 | 0.37 |
| <LimitExcept> GET | 27932 | 24114 | 0.86x | 0.40 | 0.35 |
| Satisfy Any | 27816 | 24618 | 0.89x | 0.44 | 0.33 |
| Satisfy All 403 | 39172 | 31483 | 0.80x | 0.20 | 0.27 |
| AllowMethods 405 | 40744 | 31837 | 0.78x | 0.20 | 0.27 |
| AuthMerging Or | 26935 | 23228 | 0.86x | 0.43 | 0.36 |
| AuthMerging And 403 | 39872 | 30067 | 0.75x | 0.20 | 0.30 |
| ElseIf header | 29027 | 25256 | 0.87x | 0.38 | 0.32 |
| DirectoryIndex CGI | 963 | 1787 | 1.86x | 6.84 | 2.25 |
| ErrorDocument CGI | 916 | 1572 | 1.72x | 5.40 | 2.88 |
| Basic auth 200 | 23986 | 17183 | 0.72x | 0.49 | 0.59 |
| Basic auth 401 | 44694 | 30622 | 0.69x | 0.22 | 0.41 |
| proxy static | 2925 | 2796 | 0.96x | 1.42 | 1.75 |
| <Proxy> deny | 46519 | 39124 | 0.84x | 0.18 | 0.24 |
| <ProxyMatch> allow | 2893 | 2734 | 0.94x | 1.36 | 1.59 |
| rewrite (server) | 24436 | 22648 | 0.93x | 0.47 | 0.40 |
| rewrite (.htaccess) | 20337 | 15056 | 0.74x | 0.61 | 0.55 |
| Header (.htaccess) | 23828 | 19793 | 0.83x | 0.45 | 0.41 |
| name-based vhost | 25524 | 20523 | 0.80x | 0.46 | 0.39 |
| CGI GET | 696 | 1252 | 1.80x | 11.12 | 3.25 |
| CGI POST | 662 | 1136 | 1.72x | 6.04 | 3.52 |
| HTTPS/1.1 static | 18366 | 17613 | 0.96x | 0.43 | 0.45 |
| HTTP/2 static | 14484 | 18730 | 1.29x | 0.54 | 0.41 |
| HTTP/2 10KB | 14798 | 17006 | 1.15x | 0.53 | 0.46 |
| HTTP/2 1MB | 1722 | 1821 | 1.06x | 4.61 | 4.31 |
| HTTP/2 range | 14631 | 18529 | 1.27x | 0.54 | 0.42 |
| HTTP/2 Basic auth | 15110 | 16470 | 1.09x | 0.52 | 0.47 |
| HTTP/2 vhost (SNI) | 14040 | 16759 | 1.19x | 0.56 | 0.47 |
| HTTP/2 CGI GET | 542 | 1144 | 2.11x | 7.44 | 3.49 |
| HTTP/2 CGI POST | 532 | 1134 | 2.13x | 7.63 | 3.52 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 25.9 ms | 6.5 ms |
| processes after load | 5 | 17 |
| threads after load | 209 | 99 |
| PSS after load | 49.2 MiB | 54.4 MiB |

## Reading the numbers

- 33 scenario(s) were below Apache in this run; see the table (tiny, metadata-heavy HTTP/1 paths are the usual remaining cases).
- The feature-rich conformance configuration adds conditional rules, cache lookups, `.htaccess` candidates, vhost selection and proxy matching to every request; compare these ratios with the static `bench.py` results rather than treating them as a core-server regression.
- CGI now runs through a pool of small single-threaded worker processes. They are created only when the configuration can dispatch CGI; without CGI the server remains one process.
- The process count above includes the 16 CGI workers started for this CGI-capable config. PSS still includes their shared pages.
- HTTP/2 large-file throughput uses blocking-pool positional reads and bounded buffer reuse so one stream does not stall the other streams on a connection. mmap is used only when the verified ownership/mode predicate permits it. Apache was run with stock mod_http2 settings and was not tuned.
- Not timed here: request-smuggling rejection, pipelining, HTTP/1.0, TLS 1.2/1.3, SNI certificate selection, graceful shutdown and log formatting. These are covered by `tests/conformance.py` (157 tests, all passing).
