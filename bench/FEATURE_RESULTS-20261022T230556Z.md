# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T23:04:49.559092+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 static | 53534 | 337328 | 6.30x | 19.09 | 2.66 |
| HTTP/2 10KB | 48462 | 195414 | 4.03x | 21.01 | 3.60 |
| HTTP/2 1MB | 4212 | 3567 | 0.85x | 9.93 | 10.89 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 16.3 ms | 3.3 ms |
| processes after load | 7 | 17 |
| threads after load | 385 | 18 |
| PSS after load | 156.6 MiB | 35.3 MiB |
