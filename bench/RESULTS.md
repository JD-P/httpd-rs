# Benchmark history

Methodology: each run starts real Apache and vapached with equivalent configs,
warms up, then takes the median of three samples. Runs from
`2026-10-22T10:46` onward use `wrk` (HTTP/1.1, full runs use 3s samples and
access logs go to `/dev/null`). Quick `--quick` runs use 1s samples and are
useful for trend checks, not precise comparisons. Earlier runs used `ab`; those
Apache numbers include client-side keep-alive length failures and are kept only
as history.

Runs through 2026-10-28 used 100 connections for small files, and the old
`wrk` parser did not record its non-2xx counter. After per-client connection
admission was introduced, that workload could benchmark overload rejection
rather than successful responses. Runs from 2026-11-04 use eight connections,
the pending-connection ceiling for this single-loopback-client harness, and
strictly record non-2xx and socket errors. Pre-2026-11-04 ratios remain as
history but are not comparable with strict runs.

## 2026-10-22T10:05:47.899796+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 64262 | 72036 | 1.12x | 0.69 | 2 |
| hello.txt (1.1KB, keepalive) | 67505 | 96058 | 1.42x | 0.52 | 1 |
| 10k.bin (10KB, keepalive) | 72539 | 95896 | 1.32x | 0.52 | 2 |
| 1m.bin (1MB, keepalive) | 7305 | 5722 | 0.78x | 1.75 | 5 |

## 2026-10-22T10:22:25.706618+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 50178 | 84926 | 1.69x | 0.59 | 2 |
| hello.txt (1.1KB, keepalive) | 74392 | 106458 | 1.43x | 0.47 | 1 |
| 10k.bin (10KB, keepalive) | 71830 | 98879 | 1.38x | 0.51 | 1 |
| 1m.bin (1MB, keepalive) | 6485 | 5403 | 0.83x | 1.85 | 6 |

## 2026-10-22T10:37:38.348512+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 81781 | 127350 | 1.56x | 0.79 | 2 |
| hello.txt (1.1KB, keepalive) | 84029 | 123183 | 1.47x | 0.81 | 2 |
| 10k.bin (10KB, keepalive) | 83910 | 105674 | 1.26x | 0.95 | 2 |
| 1m.bin (1MB, keepalive) | 7198 | 7188 | 1.00x | 2.78 | 7 |

## 2026-10-22T10:42:02.640021+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 0 | 0 | 0.00x | 0.00 | 0 |
| hello.txt (1.1KB, keepalive) | 0 | 0 | 0.00x | 0.00 | 0 |
| 10k.bin (10KB, keepalive) | 0 | 0 | 0.00x | 0.00 | 0 |
| 1m.bin (1MB, keepalive) | 0 | 0 | 0.00x | 0.00 | 0 |

## 2026-10-22T10:42:21.519638+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 0 | 0 | 0.00x | 0.00 | 0 |
| hello.txt (1.1KB, keepalive) | 0 | 0 | 0.00x | 0.00 | 0 |
| 10k.bin (10KB, keepalive) | 0 | 0 | 0.00x | 0.00 | 0 |
| 1m.bin (1MB, keepalive) | 0 | 0 | 0.00x | 0.00 | 0 |

## 2026-10-22T10:42:50.387335+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 95040 | 208241 | 2.19x | 0.21 | 1 |
| hello.txt (1.1KB, keepalive) | 95403 | 206908 | 2.17x | 0.21 | 1 |
| 10k.bin (10KB, keepalive) | 90429 | 192960 | 2.13x | 0.21 | 1 |
| 1m.bin (1MB, keepalive) | 7209 | 11510 | 1.60x | 0.58 | 1 |

## 2026-10-22T10:43:32.163227+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 104338 | 107037 | 1.03x | 1.43 | 8 |
| hello.txt (1.1KB, keepalive) | 92587 | 107575 | 1.16x | 1.42 | 8 |
| 10k.bin (10KB, keepalive) | 86942 | 108535 | 1.25x | 1.30 | 7 |
| 1m.bin (1MB, keepalive) | 8886 | 12713 | 1.43x | 0.95 | 2 |

## 2026-10-22T10:46:09.771893+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 103276 | 203546 | 1.97x | 0.38 | 2 |
| hello.txt (1.1KB, keepalive) | 103741 | 202971 | 1.96x | 0.39 | 2 |
| 10k.bin (10KB, keepalive) | 97440 | 188434 | 1.93x | 0.42 | 3 |
| 1m.bin (1MB, keepalive) | 9080 | 11382 | 1.25x | 1.05 | 2 |

## 2026-10-22T11:39:05.518796+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 108252 | 202329 | 1.87x | 0.42 | 3 |
| hello.txt (1.1KB, keepalive) | 109487 | 200149 | 1.83x | 0.40 | 3 |
| 10k.bin (10KB, keepalive) | 103185 | 187030 | 1.81x | 0.40 | 3 |
| 1m.bin (1MB, keepalive) | 9157 | 11279 | 1.23x | 1.06 | 2 |

## 2026-10-22T12:35:27.690834+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 109052 | 201621 | 1.85x | 0.39 | 3 |
| hello.txt (1.1KB, keepalive) | 108308 | 200658 | 1.85x | 0.40 | 3 |
| 10k.bin (10KB, keepalive) | 101706 | 189592 | 1.86x | 0.40 | 3 |
| 1m.bin (1MB, keepalive) | 9133 | 11013 | 1.21x | 1.10 | 2 |

## 2026-10-22T12:47:04.271818+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 111610 | 205343 | 1.84x | 0.38 | 2 |
| hello.txt (1.1KB, keepalive) | 111741 | 202229 | 1.81x | 0.37 | 2 |
| 10k.bin (10KB, keepalive) | 103552 | 187482 | 1.81x | 0.40 | 3 |
| 1m.bin (1MB, keepalive) | 8476 | 11409 | 1.35x | 1.06 | 2 |

## 2026-10-22T19:12:45.134835+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 110740 | 197608 | 1.78x | 0.43 | 3 |
| hello.txt (1.1KB, keepalive) | 108395 | 197591 | 1.82x | 0.39 | 2 |
| 10k.bin (10KB, keepalive) | 102474 | 184146 | 1.80x | 0.41 | 3 |
| 1m.bin (1MB, keepalive) | 9398 | 11320 | 1.20x | 1.06 | 2 |

## 2026-10-22T19:19:06.146433+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 104596 | 193797 | 1.85x | 0.41 | 2 |
| hello.txt (1.1KB, keepalive) | 104482 | 193488 | 1.85x | 0.41 | 2 |
| 10k.bin (10KB, keepalive) | 98334 | 178414 | 1.81x | 0.43 | 3 |
| 1m.bin (1MB, keepalive) | 8759 | 11133 | 1.27x | 1.07 | 2 |

## 2026-10-22T20:07:53.803491+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 97407 | 217795 | 2.24x | 0.21 | 1 |
| hello.txt (1.1KB, keepalive) | 101889 | 191364 | 1.88x | 0.24 | 2 |
| 10k.bin (10KB, keepalive) | 78604 | 163689 | 2.08x | 0.29 | 2 |
| 1m.bin (1MB, keepalive) | 7505 | 11417 | 1.52x | 0.64 | 3 |

## 2026-10-22T20:08:33.216231+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 116174 | 212525 | 1.83x | 0.37 | 2 |
| hello.txt (1.1KB, keepalive) | 118737 | 191097 | 1.61x | 0.40 | 3 |
| 10k.bin (10KB, keepalive) | 101311 | 177833 | 1.76x | 0.45 | 3 |
| 1m.bin (1MB, keepalive) | 9712 | 11653 | 1.20x | 1.01 | 2 |

## 2026-10-22T20:10:02.015072+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 119892 | 208130 | 1.74x | 0.38 | 2 |
| hello.txt (1.1KB, keepalive) | 119354 | 206093 | 1.73x | 0.38 | 2 |
| 10k.bin (10KB, keepalive) | 112594 | 190733 | 1.69x | 0.40 | 3 |
| 1m.bin (1MB, keepalive) | 9564 | 11744 | 1.23x | 1.01 | 2 |

## 2026-10-22T20:50:05.901136+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 100684 | 221699 | 2.20x | 0.20 | 1 |
| hello.txt (1.1KB, keepalive) | 99848 | 216330 | 2.17x | 0.19 | 1 |
| 10k.bin (10KB, keepalive) | 95100 | 202950 | 2.13x | 0.21 | 1 |
| 1m.bin (1MB, keepalive) | 8278 | 11346 | 1.37x | 0.59 | 1 |

## 2026-10-22T20:57:46.730657+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 107728 | 200242 | 1.86x | 0.41 | 2 |
| hello.txt (1.1KB, keepalive) | 108114 | 194730 | 1.80x | 0.45 | 3 |
| 10k.bin (10KB, keepalive) | 92343 | 165591 | 1.79x | 0.48 | 3 |
| 1m.bin (1MB, keepalive) | 9176 | 12632 | 1.38x | 0.95 | 2 |

## 2026-10-22T21:00:53.101749+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 81999 | 191733 | 2.34x | 0.22 | 1 |
| hello.txt (1.1KB, keepalive) | 86683 | 210361 | 2.43x | 0.25 | 2 |
| 10k.bin (10KB, keepalive) | 86664 | 187577 | 2.16x | 0.23 | 1 |
| 1m.bin (1MB, keepalive) | 7992 | 10613 | 1.33x | 0.64 | 2 |

## 2026-10-22T21:02:05.841481+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 72155 | 202816 | 2.81x | 0.22 | 1 |
| hello.txt (1.1KB, keepalive) | 77094 | 195553 | 2.54x | 0.23 | 1 |
| 10k.bin (10KB, keepalive) | 74779 | 177803 | 2.38x | 0.25 | 1 |
| 1m.bin (1MB, keepalive) | 8170 | 10906 | 1.33x | 0.64 | 2 |

## 2026-10-22T21:31:19.037941+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 109462 | 291477 | 2.66x | 0.28 | 3 |
| hello.txt (1.1KB, keepalive) | 100623 | 256657 | 2.55x | 0.32 | 3 |
| 10k.bin (10KB, keepalive) | 93927 | 234125 | 2.49x | 0.32 | 3 |
| 1m.bin (1MB, keepalive) | 9027 | 11984 | 1.33x | 0.98 | 2 |

## 2026-10-22T21:34:37.984281+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 103599 | 275127 | 2.66x | 0.29 | 2 |
| hello.txt (1.1KB, keepalive) | 103122 | 265435 | 2.57x | 0.31 | 3 |
| 10k.bin (10KB, keepalive) | 94780 | 227893 | 2.40x | 0.33 | 3 |
| 1m.bin (1MB, keepalive) | 9102 | 12610 | 1.39x | 0.95 | 2 |

## 2026-10-22T21:42:34.236544+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 111416 | 277334 | 2.49x | 0.28 | 2 |
| hello.txt (1.1KB, keepalive) | 103789 | 269745 | 2.60x | 0.28 | 2 |
| 10k.bin (10KB, keepalive) | 96935 | 235492 | 2.43x | 0.32 | 2 |
| 1m.bin (1MB, keepalive) | 9189 | 11569 | 1.26x | 1.03 | 2 |

## 2026-10-23T20:06:53.596703+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 86733 | 220519 | 2.54x | 0.40 | 3 |
| hello.txt (1.1KB, keepalive) | 102083 | 221694 | 2.17x | 0.37 | 2 |
| 10k.bin (10KB, keepalive) | 93132 | 197713 | 2.12x | 0.40 | 2 |
| 1m.bin (1MB, keepalive) | 8404 | 11197 | 1.33x | 1.08 | 2 |

## 2026-10-23T20:26:06.929174+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 75182 | 229260 | 3.05x | 0.20 | 1 |
| hello.txt (1.1KB, keepalive) | 83400 | 224911 | 2.70x | 0.19 | 1 |
| 10k.bin (10KB, keepalive) | 78392 | 200770 | 2.56x | 0.22 | 1 |
| 1m.bin (1MB, keepalive) | 7651 | 10823 | 1.41x | 0.64 | 2 |

## 2026-10-23T20:37:22.666517+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 96108 | 220135 | 2.29x | 0.38 | 2 |
| hello.txt (1.1KB, keepalive) | 95933 | 214048 | 2.23x | 0.42 | 3 |
| 10k.bin (10KB, keepalive) | 86258 | 201055 | 2.33x | 0.42 | 3 |
| 1m.bin (1MB, keepalive) | 9231 | 10963 | 1.19x | 1.10 | 2 |

## 2026-10-23T21:03:32.654955+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 77373 | 240576 | 3.11x | 0.19 | 1 |
| hello.txt (1.1KB, keepalive) | 83654 | 236041 | 2.82x | 0.19 | 1 |
| 10k.bin (10KB, keepalive) | 74863 | 207262 | 2.77x | 0.23 | 1 |
| 1m.bin (1MB, keepalive) | 7485 | 11179 | 1.49x | 0.61 | 1 |

## 2026-10-24T00:01:54.211577+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 83609 | 228047 | 2.73x | 0.22 | 2 |
| hello.txt (1.1KB, keepalive) | 82258 | 222800 | 2.71x | 0.22 | 2 |
| 10k.bin (10KB, keepalive) | 70309 | 199758 | 2.84x | 0.22 | 1 |
| 1m.bin (1MB, keepalive) | 7617 | 11047 | 1.45x | 0.61 | 1 |

## 2026-10-24T22:16:21.393832+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 80608 | 210731 | 2.61x | 0.21 | 1 |
| hello.txt (1.1KB, keepalive) | 81443 | 210570 | 2.59x | 0.21 | 1 |
| 10k.bin (10KB, keepalive) | 84137 | 198751 | 2.36x | 0.21 | 1 |
| 1m.bin (1MB, keepalive) | 7796 | 10801 | 1.39x | 0.63 | 2 |

## 2026-10-24T22:19:19.241721+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 87020 | 203874 | 2.34x | 0.44 | 3 |
| hello.txt (1.1KB, keepalive) | 93665 | 191885 | 2.05x | 0.42 | 2 |
| 10k.bin (10KB, keepalive) | 94443 | 185608 | 1.97x | 0.43 | 3 |
| 1m.bin (1MB, keepalive) | 8584 | 11885 | 1.38x | 1.02 | 2 |

## 2026-10-24T23:02:39.623586+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 101155 | 216600 | 2.14x | 0.38 | 2 |
| hello.txt (1.1KB, keepalive) | 95172 | 193079 | 2.03x | 0.41 | 2 |
| 10k.bin (10KB, keepalive) | 87488 | 171844 | 1.96x | 0.49 | 3 |
| 1m.bin (1MB, keepalive) | 8785 | 11777 | 1.34x | 1.02 | 2 |

## 2026-10-27T00:27:19.615538+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 92792 | 205324 | 2.21x | 0.40 | 2 |
| hello.txt (1.1KB, keepalive) | 96773 | 188648 | 1.95x | 0.47 | 3 |
| 10k.bin (10KB, keepalive) | 89396 | 154126 | 1.72x | 0.51 | 3 |
| 1m.bin (1MB, keepalive) | 8850 | 12388 | 1.40x | 0.97 | 2 |

## 2026-10-28T15:21:16.447042+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 97728 | 195297 | 2.00x | 0.42 | 2 |
| hello.txt (1.1KB, keepalive) | 98451 | 189977 | 1.93x | 0.46 | 3 |
| 10k.bin (10KB, keepalive) | 91945 | 158626 | 1.73x | 0.51 | 3 |
| 1m.bin (1MB, keepalive) | 8614 | 11596 | 1.35x | 1.04 | 2 |

## 2026-10-28T16:20:06.696779+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 86141 | 181089 | 2.10x | 0.47 | 3 |
| hello.txt (1.1KB, keepalive) | 88745 | 175953 | 1.98x | 0.46 | 2 |
| 10k.bin (10KB, keepalive) | 83626 | 161785 | 1.93x | 0.55 | 4 |
| 1m.bin (1MB, keepalive) | 9299 | 11616 | 1.25x | 1.02 | 2 |

## 2026-11-04T08:06:33.743651+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 39356 | 34067 | 0.87x | 0.23 | 1 |
| hello.txt (1.1KB, keepalive) | 39762 | 33448 | 0.84x | 0.24 | 1 |
| 10k.bin (10KB, keepalive) | 38223 | 32142 | 0.84x | 0.25 | 1 |
| 1m.bin (1MB, keepalive) | 6599 | 11656 | 1.77x | 0.63 | 2 |

## 2026-11-04T09:15:10.768151+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 42636 | 37357 | 0.88x | 0.22 | 1 |
| hello.txt (1.1KB, keepalive) | 46437 | 41187 | 0.89x | 0.19 | 1 |
| 10k.bin (10KB, keepalive) | 38427 | 36104 | 0.94x | 0.23 | 1 |
| 1m.bin (1MB, keepalive) | 4741 | 11023 | 2.33x | 0.68 | 2 |

## 2026-11-05T00:21:29.849764+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 41663 | 44075 | 1.06x | 0.18 | 1 |
| hello.txt (1.1KB, keepalive) | 35602 | 44413 | 1.25x | 0.18 | 1 |
| 10k.bin (10KB, keepalive) | 42811 | 41789 | 0.98x | 0.19 | 0 |
| 1m.bin (1MB, keepalive) | 8310 | 12250 | 1.47x | 0.61 | 2 |

## 2026-11-05T19:59:11.491313+00:00

| scenario | apache req/s | vapache req/s | ratio | mean ms (v) | p99 ms (v) |
|---|---:|---:|---:|---:|---:|
| index.html (small, keepalive) | 42588 | 40727 | 0.96x | 0.20 | 1 |
| hello.txt (1.1KB, keepalive) | 43419 | 41164 | 0.95x | 0.20 | 1 |
| 10k.bin (10KB, keepalive) | 37193 | 38459 | 1.03x | 0.21 | 1 |
| 1m.bin (1MB, keepalive) | 8108 | 11184 | 1.38x | 0.67 | 2 |
