# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T23:01:05.868382+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 1MB | 4237 | 3376 | 0.80x | 10.05 | 10.86 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 16.2 ms | 3.2 ms |
| processes after load | 5 | 17 |
| threads after load | 222 | 18 |
| PSS after load | 86.8 MiB | 110.7 MiB |
