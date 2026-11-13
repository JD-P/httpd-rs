# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T22:50:28.031472+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 static | 46894 | 276328 | 5.89x | 21.74 | 3.27 |
| HTTP/2 10KB | 42679 | 164580 | 3.86x | 23.05 | 4.39 |
| HTTP/2 1MB | 4136 | 2966 | 0.72x | 9.91 | 15.29 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 16.3 ms | 2.2 ms |
| processes after load | 7 | 17 |
| threads after load | 385 | 18 |
| PSS after load | 151.4 MiB | 36.3 MiB |
