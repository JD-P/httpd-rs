# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T22:48:38.998529+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| CGI GET | 1816 | 3950 | 2.18x | 18.61 | 8.24 |
| CGI POST | 1757 | 4932 | 2.81x | 9.11 | 3.24 |
| HTTP/2 CGI GET | 1348 | 3416 | 2.54x | 192.97 | 75.48 |
| HTTP/2 CGI POST | 1218 | 4706 | 3.86x | 53.16 | 13.57 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 15.9 ms | 3.5 ms |
| processes after load | 1 | 17 |
| threads after load | 1 | 18 |
| PSS after load | 0.0 MiB | 21.9 MiB |
