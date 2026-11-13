# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T22:57:24.248858+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 static | 49464 | 286328 | 5.79x | 20.64 | 3.13 |
| HTTP/2 10KB | 42354 | 175530 | 4.14x | 24.12 | 4.10 |
| HTTP/2 1MB | 4082 | 3306 | 0.81x | 10.44 | 11.04 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 15.8 ms | 3.4 ms |
| processes after load | 7 | 17 |
| threads after load | 385 | 18 |
| PSS after load | 158.8 MiB | 113.5 MiB |
