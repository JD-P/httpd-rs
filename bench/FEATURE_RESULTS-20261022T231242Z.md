# Feature benchmark: httpd-rs vs. Apache httpd

Generated: 2026-10-22T23:10:51.231225+00:00

Method: 3 x 2s samples per server after warm-up; access logs to /dev/null. `wrk` for cleartext HTTP/1.1, `ab` for HEAD/POST, `h2load` for TLS/HTTP/2.

| feature | apache req/s | httpd-rs req/s | ratio | apache mean ms | httpd-rs mean ms |
|---|---:|---:|---:|---:|---:|
| HTTP/2 static | 52580 | 299656 | 5.70x | 19.40 | 2.99 |
| HTTP/2 10KB | 50260 | 194018 | 3.86x | 20.20 | 3.70 |
| HTTP/2 1MB | 4967 | 5052 | 1.02x | 10.78 | 9.29 |
| HTTP/2 CGI GET | 982 | 3376 | 3.44x | 262.50 | 75.71 |
| HTTP/2 CGI POST | 1100 | 4808 | 4.37x | 58.08 | 13.31 |

## Startup checks

| metric | apache | httpd-rs |
|---|---:|---:|
| config test (`-t`) median | 17.4 ms | 3.4 ms |
| processes after load | 1 | 1 |
| threads after load | 1 | 1 |
| PSS after load | 0.0 MiB | 0.0 MiB |
