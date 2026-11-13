# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T22:42:34.203030+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| CGI GET | 2412 | 898 | 0.37x | 14.34 | 37.06 |
| HTTP/2 CGI GET | 1348 | 768 | 0.57x | 188.39 | 334.70 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 18.3 ms | 2.3 ms |
| processes after load | 7 | 1 |
| threads after load | 385 | 33 |
| PSS after load | 53.4 MiB | 10.0 MiB |
