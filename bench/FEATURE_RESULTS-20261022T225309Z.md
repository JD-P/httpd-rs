# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T22:52:02.525820+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 static | 48826 | 316296 | 6.48x | 20.85 | 2.83 |
| HTTP/2 10KB | 43070 | 166929 | 3.88x | 23.71 | 4.36 |
| HTTP/2 1MB | 4128 | 3147 | 0.76x | 10.13 | 15.02 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 17.1 ms | 3.6 ms |
| processes after load | 7 | 17 |
| threads after load | 385 | 18 |
| PSS after load | 151.9 MiB | 36.4 MiB |
