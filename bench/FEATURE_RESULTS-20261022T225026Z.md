# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T22:49:56.241011+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| rewrite (.htaccess) | 61341 | 70854 | 1.16x | 1.46 | 1.12 |
| Header (.htaccess) | 73489 | 123876 | 1.69x | 1.14 | 0.54 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 17.1 ms | 3.3 ms |
| processes after load | 7 | 17 |
| threads after load | 313 | 18 |
| PSS after load | 27.1 MiB | 21.7 MiB |
