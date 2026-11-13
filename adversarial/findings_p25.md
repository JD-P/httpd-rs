# Pass 25 — adversarial break of HEAD `fbb26fd` (static hosting: trailing-slash ACL bypass and stalled-download worker exhaustion)

- **Date:** 2026-10-30
- **Subject:** `target/release/httpd-rs` built at HEAD `fbb26fd`
  (`Fix static response policy and validator flaws`). No product source was
  edited.
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` (+ `authz_core`,
  `authz_host`, `mime`, `dir`, `headers`, `deflate`, `filter`, `autoindex`,
  `rewrite`), loopback only.
- **Harnesses:** `adversarial/p25/exploit_p25.py` (P25-A, 30 verdicts) and
  `adversarial/p25/exploit_p25_dos.py` (P25-B, 7 verdicts). Both start
  Apache and httpd-rs with equivalent configurations on sibling loopback
  ports.
- **Retained evidence:** harness output reproduced below; `/tmp/opencode/p25-*`
  fixtures and raw measurements (harness temp trees are removed unless
  `--keep`).
- **Method:** static-serving source review of the last two commits, an
  exhaustive conditional/range/compression status matrix against Apache, a
  targeted trailing-slash differential, and stalled-client timing probes
  (`ss -tin`, `/proc/<pid>/task` counts).

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P25-A** | A URL whose canonical path ends in `/` still resolves to a regular static file and is served. Apache rejects a trailing slash on a non-directory target with `404`; httpd-rs serves the file. Because the URL identity used for authorization keeps the slash (`CanonicalTarget::url_path`) while the served object is the slash-less file, every URL-anchored guard is skipped: `<LocationMatch "^/private\.txt$"> Require all denied`, `<If "%{REQUEST_URI} == '/private.txt'"> Require all denied`, and a per-directory `RewriteRule ^private\.txt$ - [F]` all deny the exact URL on both servers, but `GET /private.txt/` returns the protected bytes on httpd-rs and `404` on Apache. Requests for `//private.txt/`, `/a/../private.txt/` and `%2f` variants map to the same file. `<Files>`/`<FilesMatch>` (basename) and `<Directory>` (filesystem) guards still bind, so the exposure is limited to URL-path-scoped rules — but those are exactly how a static host gates an individual download. | `404` for `/private.txt/` (the exact-URL guard never has to cover the slash spelling) | `200` + `SECRET-CONTENT` | authorization bypass → protected static file disclosure / request-policy bypass |
| **P25-B** | A static response whose body does not fit the socket buffers and whose client stops reading blocks the connection thread in `sendfile(2)` for **≈5.15 × `Timeout`** (measured: 10.26 s at `Timeout 2`, 25.79 s at `Timeout 5`; default `Timeout 60` ⇒ ≈5 minutes), instead of being aborted at `Timeout`. A single stalled worker cannot be recovered early: the client can resume reading at any point before the ≈5× deadline and the server completes the whole transfer (256 MiB delivered after a 10 s stall with `Timeout 3`). With `MaxRequestWorkers 8` and two source addresses, 8 stalled downloads make a fresh client receive `503 Server busy`; the same 8 stalls against Apache `mpm_event` leave the fresh client at `200`. Default `MaxRequestWorkers` is 512 with a 32-connection per-source cap, so 16 source identities (or 16 IPv6 /64s) sustain full worker exhaustion by re-arming a few connections per second. | `mpm_event` frees the worker when the socket is not writable; a stalled client sees only the pre-buffered ~2.5 MiB and `EOF` at `Timeout` | worker pinned for ~5×`Timeout`; all workers can be pinned by stalled downloads | remote unauthenticated worker-exhaustion DoS (whole-server) |

P25-B is the pass-25 breakthrough: it is remote, unauthenticated, works with
the stock static recipe, and the amplification is bounded only by
`MaxRequestWorkers` and `Timeout` (the violation of the latter is the bug).
P25-A is a clean, reproducible access-control bypass on the same static
surface.

---

## 2. P25-A — trailing-slash static URLs bypass URL-anchored authorization

### 2.1 Root cause

`CanonicalTarget::from_raw_path` (`crates/server/src/request_plan.rs:55-76`)
decodes the request target, records whether it ended with `/`, normalizes the
(duplicate-slash-free, dot-free) mapping form in `norm`, and re-appends the
slash to the *textual* `url_path`:

```rust
let trailing_slash = decoded.len() > 1 && decoded.ends_with(b"/");
let norm = normalize_uri_path(&decoded)...;   // "/private.txt"  (slash dropped)
let mut url_path = String::from_utf8(norm.clone())...;
if trailing_slash && url_path != "/" {
    url_path.push('/');                        // "/private.txt/" (policy identity)
}
```

`RequestPlan::resolve` maps `norm` through `map_path()` and opens
`root.join(rel)` (`crates/server/src/request_plan.rs:214-269`). In
`dispatch_inner`, `resolve_target_checked(&root, &rel, ...)`
(`crates/server/src/server.rs:3081`) therefore resolves `private.txt` to a
`Target::File` regardless of the URL spelling, and the file is served at
`:3273`:

```rust
serve_file(cfg, scope, req, file, &meta, actual_path.as_ref(), name, ...)
```

Nothing between canonicalization and `serve_file` requires a `/`-terminated
URL to name a directory. Authorization, however, uses `url_path`:
`bind_target_grant` / `authorize_resolved_target` evaluate
`<Location>`/`<LocationMatch>`/`<If>` and per-directory rewrite rules against
`/private.txt/`. An anchored pattern such as `^/private\.txt$` does not match;
Apache 2.4.69, by contrast, rejects a trailing slash on a non-directory
target with `404` (its directory walk requires the final object to be a
directory unless a PATH_INFO-capable handler consumes the suffix), so the
same operator rule is complete on Apache.

The behaviour is not an accident of one rule kind: the per-directory rewrite
subject is built by `layer_subject` (`crates/server/src/request_plan.rs:143`),
which appends `/` to the subject when `url_path` ends in `/`, so
`RewriteRule ^private\.txt$ - [F]` misses `/private.txt/` as well.

### 2.2 Live evidence

`python3 adversarial/p25/exploit_p25.py`:

```text
== A main-config anchored LocationMatch
  PASS exact URL denied (apache): got='403' want='403'
  PASS exact URL denied (httpd-rs): got='403' want='403'
  PASS slash URL apache 404 (has no secret): got=('404', False) want=('404', False)
  PASS slash URL httpd-rs serves secret: got=('200', True) want=('200', True)
  PASS control public file slash (apache): got=('404', False) want=('404', False)
  PASS control public file slash (httpd-rs): got=('200', b'hello\n') want=('200', b'hello\n')
  PASS httpd-rs alive: got=None want=None
== B .htaccess anchored RewriteRule [F]
  ... same four exploit/control rows ...
== C main-config anchored <If REQUEST_URI>
  ... same four exploit/control rows ...
== D positive control slash-tolerant LocationMatch
  PASS slash URL apache denied: got=('403', False) want=('403', False)
  PASS slash URL httpd-rs denied: got=('403', False) want=('403', False)
== E basename <Files> guard control
  PASS slash URL apache denied: got=('403', False) want=('403', False)
  PASS slash URL httpd-rs denied: got=('403', False) want=('403', False)

P25 battery: PASS
```

(`PASS` here means "matches the recorded differential".) Group A raw
response on httpd-rs for `/private.txt/`:

```text
HTTP/1.1 200 OK
Content-Type: text/plain; charset=UTF-8
Last-Modified: ...
ETag: "..."
Accept-Ranges: bytes
Content-Length: 15
...
SECRET-CONTENT
```

Apache answers `404 Not Found` for the same request; its custom 404 body is
returned on both the exact-URL-denied and the slash spellings.

The retained conditional/range matrix (`/tmp/opencode/p25/statusmatrix.py`
run) also showed `/hello.txt//` (double trailing slash) serving the file on
httpd-rs and `404` on Apache.

### 2.3 Reachability and threat model

- Any static deployment that gates an individual resource with a URL-scoped
  rule is affected. The battery covers the three common shapes:
  `<LocationMatch>`, `<If "%{REQUEST_URI} ...">`, and per-directory
  `RewriteRule ... [F]`; `<LocationMatch ".../private\.txt$"> Require
  valid-user` is the same shape with authentication.
- Variants: `/private.txt/`, `/private.txt//`, `/a/../private.txt/`, and (with
  `AllowEncodedSlashes On`) `/private.txt%2f` all reach the same file.
- Not affected: `<Files>`/`<FilesMatch>` (basename identity) and
  `<Directory>`/`<DirectoryMatch>` (filesystem identity); both are shown as
  positive controls in the battery. Redirect/alias rules anchored with `$`
  are affected in the same way (they simply do not fire and the file is
  served).
- The project's own `README.md` presents `<Location>`-scoped guards as part
  of the static-hosting surface, and the benchmark/conformance configuration
  uses anchored `<Location>`/`<LocationMatch>`-shaped rules.

### 2.4 Impact

Unauthenticated read of files that the operator believes are protected,
from any listener/vhost served by the process, plus bypass of any
redirect/write/deny rule keyed to the exact URL. No upload primitive is
required. (Anchored URL rules around CGI scripts are a weaker case: Apache
itself executes `/script.cgi/` as PATH_INFO and does not apply the anchored
`<LocationMatch>`, so that configuration shape is already broken on Apache
and is not claimed here.)

### 2.5 Remediation direction

1. In the static sink path (after `resolve_target_checked` returns
   `Target::File` and the effective handler is `default-handler`/none),
   reject a request whose canonical URL path ends in `/` with Apache's
   `404` — do not serve the slash-less file. The check must run before
   `serve_file`, and it must not break the CGI/FastCGI PATH_INFO parity
   (`/script.cgi/` execution) that Apache provides through a real handler.
2. Alternatively, keep the trailing-slash identity but require every
   URL-scoped authorization evaluation to also consider the slash-less
   canonical form (or make the static target selection itself fail closed
   when `url_path` and the resolved object disagree about directory-ness).
3. Add differential rows for `/file.txt/`, `/file.txt//`,
   `/dir/../file.txt/` and an anchored `<LocationMatch>`/`RewriteRule`
   guard to `tests/conformance.py`; the current suite has no trailing-slash
   row for a regular file.

---

## 3. P25-B — stalled static downloads pin worker threads for ~5× `Timeout`

### 3.1 Root cause

The plain-TCP accept loop sets a socket write timeout from `Timeout`:

```rust
// crates/server/src/server.rs:357-358
stream.set_read_timeout(Some(Duration::from_secs(20))).ok();
stream.set_write_timeout(Some(cfg.timeout)).ok();
```

but the file-body writer does not enforce its own deadline. `write_response`
(`crates/server/src/http.rs:1325-1372`) sends a `Body::File` with a blocking
`sendfile(2)` loop on the raw TCP descriptor:

```rust
if let Some(fd) = stream.raw_fd() {
    while remaining > 0 {
        let n = unsafe { libc::sendfile(fd, file.as_raw_fd(), &mut off as *mut i64, chunk) };
        if n < 0 { break; }       // no EAGAIN-vs-timeout distinction, no deadline
        if n == 0 { break; }
        sent += n as u64;
        remaining -= n as u64;
    }
}
// fallback copy path only after the sendfile loop exits
```

When the client stops reading, the server fills its send queue and blocks in
the kernel. `SO_SNDTIMEO` does not bound that wait the way the code assumes:
the worker is released only after **≈5.15 × `Timeout`** (measured), not at
`Timeout`. During the whole window the response is still live — a client
that resumes reading before the ≈5× deadline receives the complete file
(256 MiB after a 10 s stall at `Timeout 3`). The connection guard
(`crates/server/src/server.rs:417-454`) counts every accepted connection
against the process-wide limit `max_request_workers` (default 512) with a
32-connection cap per source identity (`server.rs:265,409-415`), so pinned
connections directly exhaust the service.

Apache's `mpm_event` keeps the worker on the poll set while the socket is not
writable and aborts the stalled response at `Timeout` (verified below).

### 3.2 Live evidence

Worker exhaustion (`python3 adversarial/p25/exploit_p25_dos.py`,
`MaxRequestWorkers 8`, `Timeout 2`, 8 stalled downloads from 127.0.0.2/3):

```text
== httpd-rs worker pinning
  PASS control request: got='200' want='200'
  PASS fresh client rejected while stalls held: got='503' want='503'
  PASS stalled workers survive past Timeout: got=True want=True
  PASS recovery after stalls close: got='200' want='200'
== apache mpm_event control
  PASS control request: got='200' want='200'
  PASS fresh client served while stalls held: got='200' want='200'
  PASS recovery after stalls close: got='200' want='200'

P25-B battery: PASS
```

During the httpd-rs scenario, `ss -tin` showed 8 `ESTAB` connections with
`Send-Q ≈ 2.6 MiB` and `rwnd_limited` while the fresh source received
`HTTP/1.1 503 Service Unavailable`. After the stalls closed, the fresh source
returned to `200`.

Worker lifetime scaling (`/tmp/opencode/p25/probe_lifetime_scaling.py`,
`/proc/<pid>/task` polled until the connection thread exits):

```text
Timeout=2s -> worker released after 10.26s (ratio=5.13)
Timeout=5s -> worker released after 25.79s (ratio=5.16)
Timeout=10s -> worker released after 51.32s (ratio=5.13)
```

Default `Timeout 60` therefore holds a worker for ≈5 minutes. A single stalled
connection is also *resumable* during that window:

```text
httpd-rs: (268366043 bytes, True /*closed*/, 0.07s to resume)   # Timeout 3, 10s stall, 256 MiB file
apache : (2544448 bytes, True /*closed*/, 0.00s)               # only the pre-buffered bytes; EOF at Timeout
```

Apache delivered only the bytes already buffered before its `Timeout` and
closed; httpd-rs delivered the entire remaining file after the stall.

### 3.3 Attack economics

- Trigger: one `GET` (or any range ≥ a few MiB) of any static object larger
  than the kernel socket buffers (observed `Send-Q ≈ 2.6 MiB`; default
  `tcp_wmem` max 4 MiB). Asset hosts serve multi-MiB bundles/videos
  routinely.
- Cost: one TCP connection and one request per pinned worker; the client
  never reads. Default caps allow 32 connections per IPv4 source identity
  and 512 total, so 16 source identities (or 16 IPv6 /64s) pin every worker.
- Sustainability: each pin lasts ≈5×`Timeout`; re-arming 16×32 connections
  every ~5 minutes (≈1.7 requests/second) keeps the process saturated, and
  every other client receives `503 Server busy` on a plain listener (or has
  the TLS connection dropped) at accept time.
- Apache with the same `MaxRequestWorkers 8`/`Timeout 2` serves other clients
  throughout.

### 3.4 Remediation direction

1. Give file sends an **absolute deadline**: after each `sendfile` chunk,
   check a per-response write deadline derived from `Timeout`; on expiry,
   abort the response and close the connection. Prefer non-blocking sockets
   plus `poll(POLLOUT)`/`SO_SNDTIMEO` with explicit deadline arithmetic so the
   kernel’s EAGAIN returning is distinguishable from progress.
2. Charge each in-flight static file send against a process-wide
   “blocking response write” budget (mirroring the existing blocking-read
   leases), and drop the oldest stalled writers when the budget or deadline
   is exceeded.
3. Regression: a non-reading client must see the connection closed (and the
   worker released) within a small multiple of `Timeout`; assert in the
   retained battery as in P25-A.

---

## 4. Other divergences examined (not reported as vulnerabilities)

The conditional/range/compression matrix (`/tmp/opencode/p25/statusmatrix.py`,
`condmatrix.py`) produced only these additional status differences; each was
checked and judged a parity/documentation matter rather than a security bug:

| Case | Apache | httpd-rs | Note |
|---|---|---|---|
| `bytes=-0` | `200` (ignores the suffix) | `416` | httpd-rs follows RFC 9110’s unsatisfiable-suffix reading; both are internally consistent. |
| `bytes=0-99999999999999999999` | `200` (ignores overflow) | `206` full-content | httpd-rs treats an overflowing end as `len-1`; no amplification (single range only). |
| `If-None-Match: *` + `If-Modified-Since` | `200` | `304` | RFC 9110 requires `If-None-Match` precedence and ignoring `If-Modified-Since`; httpd-rs is the RFC-correct side. |
| `Range` + `Accept-Encoding: br` | `206` over the Brotli bytes (`/16`) | `206` over identity bytes (`/12`) | httpd-rs’s documented “ranges bypass compression” policy; each server’s `Content-Range`/ETag pair is self-consistent. |
| `GET *` / `HEAD *` | `400` | `200` root index (`CanonicalTarget::from_request` maps `*` to `/`) | Real parity gap, but the mapped URL is still `/`, so URL-scoped rules and the cache key use the canonical root identity; no bypass reproduced. Worth a 400 for non-`OPTIONS` methods. |
| Compression bodies | different encoder output | different encoder output | Not comparable byte-for-byte; headers were consistent. |

---

## 5. Reproduction

```sh
cd /root/httpd-rs
cargo build --release -p httpd-rs
python3 adversarial/p25/exploit_p25.py        # P25-A: 30 verdicts
python3 adversarial/p25/exploit_p25_dos.py    # P25-B: 7 verdicts
```

Both batteries bind loopback ports only, start single-process Apache 2.4.69
with separate pid/error logs, and remove their fixtures unless `--keep` is
given. Scaling/lifetime evidence:

```sh
cd /tmp/opencode/p25
python3 probe_lifetime_scaling.py             # ~5.15x Timeout release ratio
python3 probe_stall_apache.py                 # httpd-rs completes after stall; Apache EOFs at Timeout
```

## 6. Retained files

- `adversarial/p25/exploit_p25.py` — P25-A differential battery.
- `adversarial/p25/exploit_p25_dos.py` — P25-B worker-exhaustion battery.
- `/tmp/opencode/p25/` — matrix/fuzzer/lifetime probes and raw outputs
  (`statusmatrix.py`, `condmatrix.py`, `probe_stall_apache.py`,
  `probe_lifetime_scaling.py`, `lifetime_scaling.out`).
- `/tmp/opencode/p25-dos/`, `/tmp/opencode/p25-sendfile/` — 64 MiB/256 MiB
  fixtures and server logs from the timing probes.

No product source was modified; `git status` shows only the new
`adversarial/p25/` files, `adversarial/findings_p25.md` and the
`adversarial/README.md` index update.
