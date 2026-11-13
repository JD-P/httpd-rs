# Cache benchmark history

Methodology: both servers serve the same tree with `CacheEnable disk /cached/`,
`CacheHeader On`, `CacheIgnoreNoLastMod On` and a fixed `max-age`; the harness
warms each cached URL and refuses to time a scenario unless the second request
reports `X-Cache: HIT`. Each row is the median of the requested samples after a
discard warm-up run. `static 1.1KB` is the non-cached baseline. Full runs use
3s samples, three samples and 100 connections (16 for the 1 MB entry); quick
runs use 1s/one sample and omit the 1 MB case.

## 2026-10-27T00:51:16.624270+00:00

| scenario | Apache req/s | httpd-rs req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| cache HIT 1.1KB | 77934 | 148709 | 1.91x | 0.69 | 13.6 |
| cache HIT 10KB | 84754 | 143945 | 1.70x | 0.40 | 2.0 |
| static 1.1KB | 90079 | 208299 | 2.31x | 0.26 | 1.3 |

## 2026-10-27T00:51:26.773783+00:00

| scenario | Apache req/s | httpd-rs req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| cache HIT 1.1KB | 91023 | 143035 | 1.57x | 0.43 | 2.2 |
| cache HIT 10KB | 85109 | 133929 | 1.57x | 0.46 | 2.4 |
| cache HIT 1MB | 7720 | 6260 | 0.81x | 2.59 | 8.4 |
| static 1.1KB | 85510 | 196232 | 2.29x | 0.29 | 1.4 |

## 2026-10-27T01:01:19.174107+00:00

| scenario | Apache req/s | httpd-rs req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| cache HIT 1.1KB | 87007 | 145798 | 1.68x | 0.44 | 2.6 |
| cache HIT 10KB | 83005 | 145949 | 1.76x | 0.42 | 2.4 |
| cache HIT 1MB | 7424 | 11544 | 1.55x | 0.94 | 2.7 |
| static 1.1KB | 89734 | 206594 | 2.30x | 0.29 | 1.8 |

## 2026-10-27T01:10:04.892417+00:00

| scenario | Apache req/s | httpd-rs req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| cache HIT 1.1KB | 86780 | 141844 | 1.63x | 0.44 | 2.5 |
| cache HIT 10KB | 80218 | 136152 | 1.70x | 0.46 | 2.5 |
| cache HIT 1MB | 8158 | 13140 | 1.61x | 0.86 | 2.6 |
| static 1.1KB | 88894 | 207076 | 2.33x | 0.26 | 1.3 |
