# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T22:55:59.068523+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 static | 50389 | 324344 | 6.44x | 20.25 | 2.75 |
| HTTP/2 10KB | 42343 | 185938 | 4.39x | 24.02 | 3.79 |
| HTTP/2 1MB | 4100 | 3337 | 0.81x | 10.34 | 10.91 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 15.5 ms | 3.3 ms |
| processes after load | 7 | 17 |
| threads after load | 385 | 18 |
| PSS after load | 154.8 MiB | 119.0 MiB |
