# Pass 19 — adversarial break of HEAD `07c7879` ("Require stable FastCGI paths and openat2")

- **Date:** 2026-10-29
- **Subject:** `target/release/httpd-rs` built at HEAD `07c7879`. No product source was edited. The retained additions for this pass are `adversarial/p19/exploit_p19.py`, this write-up and the `adversarial/README.md` index entry.
- **Oracle:** Apache/2.4.69 (Debian), `/usr/sbin/apache2 -X`, with `mod_cache` + `mod_cache_disk`. Loopback only.
- **Harness:** `adversarial/p19/exploit_p19.py` — **4 differential verdicts**: query-keyed growth under a 1 MiB disk quota (A), header-keyed growth with the client resetting after the response headers (B), memory-bounded process death (C) and the Apache oracle on the identical fixture and cache policy (D).
- **Retained evidence:** `/tmp/opencode/p19-harness` (fixtures, configs, per-group logs, the allocator-abort log).
- **Method:** audit of the in-memory half of `crates/server/src/cache.rs` against the F44 disk-quota closure, followed by a live Apache-versus-httpd-rs differential on the project's own `bench/cache_bench.py` cache policy.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | httpd-rs HEAD | Class |
|---|---------|---------------|--------------|-------|
| **P19-A** | The shared cache keeps a complete copy of every cacheable response body in a process-global `HashMap`. The map is bounded by `MAX_ENTRIES = 4096` **keys** and `CacheMaxFileSize`, but never by bytes, and `CacheMaxDiskSize` is not consulted for the in-memory copy. A remote, unauthenticated client that forces distinct cache keys (unique query strings, or — with `CacheIgnoreQueryString On` — any unique request-header value, because the policy fingerprint hashes the complete header set) retains up to **`4096 × CacheMaxFileSize`** bytes of server heap: **≈4 GiB by default**, **≈8 GiB under the repository's own cache-benchmark policy** (`CacheMaxFileSize 2097152`), and proportionally more for any deployment that raises `CacheMaxFileSize`. | `mod_cache_disk` streams the representation to disk and stays flat: **+0 MiB RSS over 500 unique-query requests**, with a working `X-Cache: HIT`. | RSS grows **≈1 MiB per request**; with a 1 MiB `CacheMaxDiskSize` the disk cache holds **zero** entries while heap grows to hundreds of MiB. Under memory pressure the process aborts (`memory allocation of 1048576 bytes failed`) because the release profile sets `panic = "abort"`. | remote memory-exhaustion denial of service (whole-process) |

The attacker's cost per retained MiB is a single short request. Because `cache::store` runs before the response body is written, the client can read only the response headers and reset the connection (RST) and the server still retains the full body: **400 header-varied requests that never received a body grew RSS by 407 MiB** (P19-B). The attack needs no authentication, no cookies, no uploaded content and no large request body; it works with the stock `CacheEnable disk` configuration and with the exact policy the project benchmarks (`bench/cache_bench.py`).

---

## 2. Observed evidence

All four groups run loopback-only under `/tmp/opencode/p19-harness`; the fixture is a 1 MiB cacheable static file and a config matching `bench/cache_bench.py` (`CacheRoot`, `CacheEnable disk /cached/`, `CacheIgnoreNoLastMod On`, `CacheDefaultExpire 3600`, `CacheMaxExpire 3600`).

### 2.1 P19-A — memory grows while the disk quota holds nothing

```
PASS  P19-A query-key memory growth: rss +504 MiB over 500 unique-query requests;
      disk files=0 (quota 1048576 B); ceiling = MAX_ENTRIES * CacheMaxFileSize
```

`CacheMaxDiskSize 1048576` (1 MiB) is smaller than one 1 MiB body + metadata, so `disk_store()` refuses every entry and the cache directory stays empty. Heap still grows ~1 MiB per distinct query string (`/cached/1m.bin?k=<i>`). The disk-quota fix from F44 bounds the disk and nothing else.

A second run with `CacheMaxFileSize 65536` (64 KiB) and the same 1 MiB disk quota pins the ceiling formula exactly:

```
 1000 requests rss=   71.0 MiB  cache_files=30
 2000 requests rss=  134.9 MiB  cache_files=30
 3000 requests rss=  198.7 MiB  cache_files=30
 4000 requests rss=  262.6 MiB  cache_files=30
 5000 requests rss=  268.8 MiB  cache_files=30
 6000 requests rss=  268.8 MiB  cache_files=30
expected in-memory ceiling ~ 4096 * 64 KiB = 256.0 MiB
```

The plateau is `MAX_ENTRIES × CacheMaxFileSize` plus allocator overhead, independent of `CacheMaxDiskSize` and of the number of requests. With the defaults (`CacheMaxFileSize 1 MiB`) that is ≈4 GiB; with the cache benchmark's `CacheMaxFileSize 2097152` it is ≈8 GiB.

### 2.2 P19-B — the client never receives the body and the server retains it anyway

```
PASS  P19-B header-keyed growth with reset-after-headers: rss +407 MiB over 400
      header-varied requests that never received the response body
```

`CacheIgnoreQueryString On` does not help: the cache key's policy fingerprint hashes the complete request-header set, so a unique `X-Abort: <i>` header creates a unique key. Each request reads only the response head (`HTTP/1.1 200`, headers), sets `SO_LINGER` to force a RST and closes. `cache::store` has already run in `dispatch_with_scheme` before `write_response`, so the entry — including the full body read by `response_body_bytes` — is inserted and kept. The attacker's upload is ~80 bytes; the server permanently retains ~1 MiB.

### 2.3 P19-C — allocation failure kills the process

```
PASS  P19-C memory-bounded process death: pid 29953 exited=True after ~672
      requests under RLIMIT_AS=768 MiB; allocator abort=True
```

Server stderr:

```
memory allocation of 1048576 bytes failed
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

`Cargo.toml` sets `panic = "abort"` in `[profile.release]`, and Rust's allocation-error path aborts regardless; the whole server dies, not just the request. On a host or container with a memory cap smaller than `4096 × CacheMaxFileSize` (i.e. anything under ~4 GiB with the defaults) the same outcome arrives via the allocator or the cgroup OOM killer. No restart supervision, backoff or per-request containment exists: every connection thread shares the process-global cache, so one client's entries kill all tenants.

### 2.4 P19-D — Apache oracle on the identical fixture and policy

```
PASS  P19-D Apache oracle: Apache cached HIT=True, rss +0 MiB over 500
      unique-query requests (httpd-rs grew ~500 MiB in P19-A)
```

Apache is given the same tree, `CacheRoot`, `CacheEnable disk /cached/`, `CacheMaxFileSize 2097152`, `CacheIgnoreNoLastMod On`, `CacheDefaultExpire`/`CacheMaxExpire` and an explicit `Cache-Control` (Apache requires an explicit expiration for query-string URLs). It serves the same 1 MiB representation, reports `X-Cache: HIT` on the second request, and its RSS does not move across 500 unique-query requests.

---

## 3. Root cause

### 3.1 The in-memory entry owns the whole body

`crates/server/src/cache.rs:63-78`:

```rust
#[derive(Clone)]
struct Entry {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,          // complete representation, heap-owned
    ...
}

fn entries() -> &'static Mutex<HashMap<String, Vec<Entry>>> { ... }
```

`store()` (`cache.rs:1327-1456`) materializes the body through `response_body_bytes()` (`cache.rs:1040-1053`), which reads the entire `Body::File` into a fresh `Vec`, and then retains a clone in the global map:

```rust
let Some(body) = response_body_bytes(&mut resp.body) else { return; };
...
let entry = Entry { ..., body: body.clone(), ... };
{
    let mut guard = entries().lock()...;
    if guard.len() > MAX_ENTRIES && !guard.contains_key(&key) {
        if let Some(victim) = guard.keys().next().cloned() {
            guard.remove(&victim);            // one arbitrary key, no byte accounting
        }
    }
    let list = guard.entry(key.clone()).or_default();
    list.retain(|e| e.vary != entry.vary);
    list.push(entry.clone());                 // body retained
    while list.len() > MAX_VARIANTS_PER_KEY { list.remove(0); }
}
disk_store(cfg, &key, &entry);
```

`MAX_ENTRIES` (`cache.rs:28`) caps the number of **keys** at 4096. `MAX_VARIANTS_PER_KEY` (`cache.rs:34`) caps variants per key, but it cannot multiply the ceiling: the cache key's policy fingerprint hashes every request header (`cache.rs:712-721`), so a varying request header changes the key rather than creating a second variant. There is no `CacheMaxMemorySize`, no total-byte counter and no relationship to `CacheMaxDiskSize`.

### 3.2 The F44 fix only covers the disk

`disk_store()` (`cache.rs:1206-1288`) is where the F44 remediation lives: `incoming > cfg.cache.max_disk_size` refuses the entry, `MAX_DISK_ENTRIES` caps the file count, and the oldest stems are evicted under `disk_usage()`. The in-memory insertion above happens unconditionally and independently — P19-A's disk quota of 1 MiB produced an empty cache directory and a 504 MiB heap. `lookup()` also clones the retained body under the global mutex on every hit (`cache.rs:868-895`, `found = Some(entry.clone())`), so a popular 1 MiB cached object additionally memcpys 1 MiB under a process-wide lock per request.

### 3.3 Store-before-write turns reset clients into memory donors

`dispatch_with_scheme` calls `cache::store` (`server.rs:1340-1354`) before `handle_connection` calls `write_response` (`server.rs:772`). The store path does not depend on the client reading the response, so RST-after-headers (P19-B) still inserts the entry. The attacker does not have to receive the 1 MiB body to make the server keep it.

### 3.4 The release profile makes allocation failure fatal

`Cargo.toml:19` sets `panic = "abort"`. A failed `Vec` growth in `response_body_bytes` or in the retained entry aborts the process, which is what P19-C captures. Even on a host large enough to reach the ceiling, a 4-8 GiB resident cache permanently degrades every co-tenant and makes the next allocation failure fatal.

---

## 4. Exploit chain

1. The operator enables the documented cache subset, e.g. the repository's own benchmark policy:

   ```apache
   CacheRoot "/var/cache/httpd-rs"
   CacheEnable disk /cached/
   CacheHeader On
   CacheIgnoreNoLastMod On
   CacheDefaultExpire 3600
   CacheMaxExpire 3600
   CacheMaxFileSize 2097152
   ```

   (`bench/cache_bench.py:81-87`.) A default `CacheMaxFileSize` of 1 MiB behaves the same with a proportionally lower ceiling.

2. A cacheable response exists (any static file with `Last-Modified` qualifies; the harness also matches the benchmark's `CacheIgnoreNoLastMod On`).

3. The attacker requests it with a fresh key per request:

   ```
   GET /cached/1m.bin?k=0        # default: query string keys the entry
   GET /cached/1m.bin?k=1
   ...
   ```

   or, with `CacheIgnoreQueryString On`:

   ```
   GET /cached/1m.bin            # X-Abort: 0, 1, 2, ...
   X-Abort: <i>                  # any header keys the entry (fingerprint binds all)
   ```

   The client may abort after the response headers; the server keeps the body.

4. Heap grows ≈`CacheMaxFileSize` per request until `MAX_ENTRIES × CacheMaxFileSize`. On a 1-2 GiB host the process aborts with `memory allocation of <n> bytes failed` (P19-C, observed after ~672 requests under a 768 MiB address-space limit); on a larger host the resident set reaches 4-8 GiB and stays there. Apache, under the same policy, stays flat (P19-D).

---

## 5. Impact and preconditions

**Impact.** Remote, unauthenticated whole-process denial of service on any httpd-rs deployment that uses the documented `mod_cache` subset. The memory is retained process-wide and never released except by per-key expiry on lookup, `MAX_ENTRIES` eviction of one arbitrary key per new key, or a configuration reload. Because `panic = "abort"`, the terminal event is a full-process abort; without a supervisor the service stays down. A larger host is still degraded by a multi-GiB permanent working set, and the same `entries()` mutex that serves lookups also serializes stores.

**Preconditions.**

1. `CacheRoot` + `CacheEnable disk <prefix>` (or the in-memory variant of the same directives) — the documented `mod_cache` subset, exercised by `bench/cache_bench.py`.
2. At least one cacheable response under the enabled prefix. A static file with `Last-Modified` is sufficient; `CacheIgnoreNoLastMod On` extends this to files without one.
3. Anonymous requests only: `store()` refuses `Authorization`/`Cookie` requests, so the attacker sends neither.

**Severity.** High. It is not a single-packet kill: the attacker sends one short request per retained `CacheMaxFileSize` and can reset after headers, so the cost is small but linear. The critical property is that the ceiling is `4096 × CacheMaxFileSize` (≈4 GiB by default, ≈8 GiB in the repository's own benchmark), it is independent of `CacheMaxDiskSize`, and there is no containment when the allocation fails.

---

## 6. Relationship to F44 and other findings

F44 ("on-disk cache entries have no total quota or expiry cleanup; unique URLs fill the cache partition") was closed by adding `CacheMaxDiskSize`, `MAX_DISK_ENTRIES`, stem eviction and expiry cleanup. That closure is real but covers only the persisted half of the cache. P19 is the in-memory half: the same "unique URLs fill the store" primitive now fills heap instead of disk, the same `MAX_ENTRIES` count cap that F44's write-up cited as the bound is not a byte bound, and the F44 regression cases assert disk accounting only. P19 is distinct from every prior finding because it is an availability bug in a documented feature rather than an authorization/handler-identity bypass, and it needs no symlink, no `.htaccess`, no CGI/FastCGI/Proxy backend and no configuration mistake beyond enabling the cache the project benchmarks.

---

## 7. Reproduction

```sh
cargo build --release -p httpd-rs
python3 adversarial/p19/exploit_p19.py            # all four groups
python3 adversarial/p19/exploit_p19.py A B C      # skip the Apache oracle
python3 adversarial/p19/exploit_p19.py --keep     # retain fixtures and logs
```

The final retained run produced **4/4 PASS**:

```text
PASS  P19-A query-key memory growth: rss +504 MiB over 500 unique-query requests; disk files=0 (quota 1048576 B); ceiling = MAX_ENTRIES * CacheMaxFileSize
PASS  P19-B header-keyed growth with reset-after-headers: rss +407 MiB over 400 header-varied requests that never received the response body
PASS  P19-C memory-bounded process death: pid 29953 exited=True after ~672 requests under RLIMIT_AS=768 MiB; allocator abort=True
PASS  P19-D Apache oracle: Apache cached HIT=True, rss +0 MiB over 500 unique-query requests (httpd-rs grew ~500 MiB in P19-A)
```

Group C applies `RLIMIT_AS` to the child only, so the harness is safe to run on a shared host; groups A/B allocate a few hundred MiB by design and release the server afterwards.

---

## 8. Suggested remediation direction

The product source was not changed for this pass. The required behavior is a byte-bounded in-memory cache:

- **Add a memory budget.** Introduce a global in-memory byte cap (e.g. `CacheMaxMemorySize`, defaulting to a small fraction of `CacheMaxDiskSize`) and account `entry.body.len()` plus retained headers/vary bytes on insert. Evict oldest-first or refuse to retain when the budget is full, exactly like the disk path already does.
- **Prefer not to retain large bodies at all.** `lookup()` already serves cached bodies above `FILE_BODY_THRESHOLD` (64 KiB) from the persisted body file (`cache.rs:945-971`). Make that the storage policy as well: keep only small bodies in memory, and let larger entries live solely in the disk cache. That alone removes the ~4-8 GiB ceiling while keeping the benchmark's small-object hit path.
- **Do not clone the body under the global mutex.** Store entries behind an `Arc` and clone the handle for a hit; the current `entry.clone()` memcpys up to `CacheMaxFileSize` while `entries()` is locked.
- **Count bytes, not just keys, in eviction.** `guard.len() > MAX_ENTRIES` and the `lookup()` disk-load insertion (which currently skips both the entry and variant caps) should be driven by the same byte accounting as the disk quota.
- **Regression coverage.** Extend `tests/soak.py` (whose config has no `CacheRoot`/`CacheEnable`, which is why this pass went unnoticed) with a cache-enabled mode that drives unique query keys and unique headers, asserts a hard RSS ceiling across a soak, and asserts that `CacheMaxDiskSize` alone cannot produce unbounded heap. Add an Apache differential like P19-D to the cache benchmark so the memory profile, not just the hit rate, is compared.
