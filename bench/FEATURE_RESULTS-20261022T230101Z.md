# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T22:59:54.533790+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 static | 47793 | 327704 | 6.86x | 21.38 | 2.73 |
| HTTP/2 10KB | 42824 | 174567 | 4.08x | 23.04 | 4.09 |
| HTTP/2 1MB | 4136 | 3367 | 0.81x | 10.22 | 10.70 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 15.4 ms | 3.3 ms |
| processes after load | 7 | 17 |
| threads after load | 385 | 18 |
| PSS after load | 139.5 MiB | 123.6 MiB |
