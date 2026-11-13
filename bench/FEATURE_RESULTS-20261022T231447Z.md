# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T23:12:56.683448+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 static | 50774 | 304072 | 5.99x | 20.15 | 2.94 |
| HTTP/2 10KB | 44697 | 175187 | 3.92x | 22.73 | 4.12 |
| HTTP/2 1MB | 4795 | 5406 | 1.13x | 11.07 | 8.83 |
| HTTP/2 CGI GET | 1232 | 3364 | 2.73x | 206.21 | 76.04 |
| HTTP/2 CGI POST | 1124 | 5108 | 4.54x | 56.72 | 12.52 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 16.9 ms | 3.3 ms |
| processes after load | 7 | 17 |
| threads after load | 385 | 18 |
| PSS after load | 147.2 MiB | 36.8 MiB |
