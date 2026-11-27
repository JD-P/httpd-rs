# musl allocator comparison

## 2026-11-27: mimalloc retention

The production static target was built twice from the same worktree and lock
file for `x86_64-unknown-linux-musl`. The baseline used `mimalloc` 0.1.52; the
candidate used musl's default allocator. `wrk` used four client threads, eight
keep-alive connections, five-second samples and three alternating-order rounds.
The table reports the median round so host drift does not systematically favor
one allocator.

| response | mimalloc req/s | musl req/s | musl throughput change | mimalloc mean / p99 ms | musl mean / p99 ms |
|---|---:|---:|---:|---:|---:|
| 64 B HTML | 44,697 | 18,135 | -59.4% | 0.189 / 0.566 | 0.478 / 1.330 |
| 1.1 KiB text | 46,085 | 17,502 | -62.0% | 0.187 / 0.621 | 0.464 / 1.280 |
| 10 KiB static | 42,742 | 17,664 | -58.7% | 0.192 / 0.593 | 0.484 / 1.450 |
| 1 MiB static | 12,475 | 10,613 | -14.9% | 0.664 / 3.030 | 0.766 / 2.120 |

Median process high-water RSS fell from 73.4 MiB to 14.2 MiB and median
virtual size fell from 1,180.8 MiB to 155.6 MiB. The static PIE shrank from
10,215,024 to 10,051,104 bytes. The default allocator produced no failed or
non-successful responses; the mimalloc build produced one non-successful 1 MiB
response across its three measured samples.

The dependency reduction is not worth this regression. The musl release keeps
`mimalloc` as its global allocator: removing it would eliminate the `mimalloc`
and `libmimalloc-sys` packages and materially reduce memory reservation, but
would cut allocation-heavy small-response throughput by roughly 59–62%.
