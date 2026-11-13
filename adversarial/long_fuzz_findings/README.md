# Long-fuzz findings

`tests/long_fuzz.sh` retains crash, timeout and out-of-memory inputs here,
grouped by fuzz target. The campaign uses libFuzzer fork mode so an individual
finding is archived without ending the remaining scheduled work.

Replay a retained input from the repository root with the command printed by
the campaign, for example:

```sh
cargo +nightly-2026-10-29 fuzz run TARGET \
  adversarial/long_fuzz_findings/TARGET/ARTIFACT -- -runs=1
```

Do not use this directory as a seed corpus: an unresolved crashing input in a
corpus would make every ordinary libFuzzer startup fail immediately. Once a
finding has been classified, it can be moved into the corresponding
pass-specific evidence directory and converted into a regression test.
