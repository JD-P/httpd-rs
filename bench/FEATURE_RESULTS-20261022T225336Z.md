# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T22:53:14.246746+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 1MB | 4054 | 3211 | 0.79x | 10.27 | 14.22 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 17.7 ms | 3.3 ms |
| processes after load | 5 | 17 |
| threads after load | 215 | 18 |
| PSS after load | 80.5 MiB | 16.1 MiB |
