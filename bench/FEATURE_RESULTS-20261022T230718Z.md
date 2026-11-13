# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T23:06:11.314691+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 static | 52678 | 300392 | 5.70x | 19.38 | 3.01 |
| HTTP/2 10KB | 44624 | 176572 | 3.96x | 22.04 | 4.05 |
| HTTP/2 1MB | 4196 | 3556 | 0.85x | 10.21 | 10.82 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 15.2 ms | 3.2 ms |
| processes after load | 7 | 17 |
| threads after load | 385 | 18 |
| PSS after load | 155.9 MiB | 35.8 MiB |
