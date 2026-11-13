# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T22:58:36.516378+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 1MB | 3866 | 3280 | 0.85x | 10.98 | 11.01 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 16.1 ms | 3.5 ms |
| processes after load | 5 | 17 |
| threads after load | 217 | 18 |
| PSS after load | 78.8 MiB | 110.4 MiB |
