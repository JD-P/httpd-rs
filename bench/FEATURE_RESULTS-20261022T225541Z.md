# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T22:54:34.765622+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 static | 51342 | 176840 | 3.44x | 19.89 | 5.08 |
| HTTP/2 10KB | 43500 | 116046 | 2.67x | 23.38 | 6.00 |
| HTTP/2 1MB | 4054 | 3326 | 0.82x | 10.06 | 10.71 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 15.2 ms | 3.2 ms |
| processes after load | 7 | 17 |
| threads after load | 385 | 18 |
| PSS after load | 155.5 MiB | 133.7 MiB |
