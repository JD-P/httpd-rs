# Adversarial yield

> This is a measure of demonstrated vulnerability impact returned by the
> recorded adversarial searches per search-hour. It is not an estimate of
> vulnerabilities remaining and is not an absolute security score.

## Formula

For each confirmed finding:

- impact weights are low `1`, medium `10`, high `100`, critical `1000`,
  and catastrophic `10000`;
- `b` is the recovered number of unintended behaviors that had to compose;
- the composition factor is `2^(1-b)`, halving the contribution for each
  additional required unintended behavior; and
- the finding contributes `impact weight × composition factor` points.

The reported score is:

```text
adversarial yield = sum(finding points) / logical-search hours
```

Only confirmed findings enter the numerator. Duplicate, invalid and
unresolved claims do not. Every completed logical search enters the
denominator, including a search with no confirmed finding. Durations are
the sum of its segment intervals; outage gaps between interrupted and
resumed segments are excluded.

The decimal scale is meaningful only for comparisons made with the same
formula. Multiplying every impact weight by a constant would change the
number but not the trend.

## Whole recovered history

| Search hours | Searches | Confirmed findings | Findings/hour | Raw impact points | Composition-adjusted points | Adversarial yield |
|---:|---:|---:|---:|---:|---:|---:|
| 15.467 | 41 | 132 | 8.53 | 57444.0 | 15909.5 | **1028.64** |

Impact tiers: critical 52, high 52, medium 24, low 4.

Recovered unintended-behavior counts: 2 behaviors: 72 findings, 3 behaviors: 37 findings, 4 behaviors: 23 findings.

### Contribution by primary family

These values decompose the whole-history score. They do not compare family
convergence because the time was not allocated uniformly across families.

| Primary family | Confirmed findings | Adjusted points | Share of points | Points per whole-history hour |
|---|---:|---:|---:|---:|
| `authority_bypass` | 19 | 652.5 | 4.1% | 42.19 |
| `code_execution` | 41 | 8062.5 | 50.7% | 521.29 |
| `denial_of_service` | 28 | 4360.0 | 27.4% | 281.90 |
| `information_disclosure` | 25 | 2643.5 | 16.6% | 170.92 |
| `integrity_violation` | 10 | 70.0 | 0.4% | 4.53 |
| `protocol_confusion` | 1 | 5.0 | 0.0% | 0.32 |
| `server_request_abuse` | 3 | 100.0 | 0.6% | 6.47 |
| `unclassified` | 5 | 16.0 | 0.1% | 1.03 |

## Within-family result

The reviews deliberately changed vulnerability families over time. A simple
chronological total therefore confounds code improvement with the start of a
fresh campaign. The primary convergence comparison uses only searches whose
recovered `requested_focus` explicitly names the outcome family, and compares
the first half with the second half of that family's searches. Broad/general
searches are not assigned to a family after the fact.

Only findings whose primary family matches the campaign enter its numerator;
all time from the selected searches enters its denominator.

| Family | Half | Searches | Hours | Matching findings | Findings/hour | Critical | High | Medium | Low | Adjusted points | Yield/hour | Change |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `code_execution` | first | S14, S15, S16, S18, S20 | 2.301 | 21 | 9.12 | 20 | 1 | 0 | 0 | 4637.5 | 2015.09 | — |
| `code_execution` | second | S21, S22, S23, S24, S25 | 2.577 | 9 | 3.49 | 6 | 3 | 0 | 0 | 1500.0 | 582.07 | -71.1% |
| `denial_of_service` | first | S26, S27, S28, S29, S31 | 0.856 | 8 | 9.34 | 1 | 6 | 1 | 0 | 780.0 | 911.01 | — |
| `denial_of_service` | second | S34, S35, S36, S37, S38, S39 | 3.368 | 12 | 3.56 | 7 | 5 | 0 | 0 | 3450.0 | 1024.21 | +12.4% |

Within the explicitly code-execution-focused searches, matching findings
per hour changed -61.7% and severity/composition-adjusted
yield changed -71.1%.
Within the explicitly denial-of-service-focused searches, matching
findings per hour changed -61.9%, but adjusted yield
changed +12.4%:
later findings were rarer but more severe. Thus the code-execution
campaign shows convergence on both measures; the denial-of-service
campaign shows lower finding frequency, not lower demonstrated harm per
hour.

## Sensitivity within focused campaigns

The impact-tier jumps remain fixed while the composition discount is
varied. The within-family conclusions do not depend on the selected
composition rule.

| Family | Discount | First half | Second half | Second vs first |
|---|---|---:|---:|---:|
| `code_execution` | impact only | 8733.88 | 2444.71 | -72.0% |
| `code_execution` | reciprocal | 2799.04 | 795.50 | -71.6% |
| `code_execution` | halving (reported) | 2015.09 | 582.07 | -71.1% |
| `code_execution` | three-level | 2617.99 | 630.58 | -75.9% |
| `denial_of_service` | impact only | 1880.43 | 2226.55 | +18.4% |
| `denial_of_service` | reciprocal | 920.75 | 1053.90 | +14.5% |
| `denial_of_service` | halving (reported) | 911.01 | 1024.21 | +12.4% |
| `denial_of_service` | three-level | 911.01 | 1024.21 | +12.4% |

## Cross-family workload history

For completeness, this is the combined yield in fixed groups of ten
chronological searches (the last has nine). It describes what the review
process found over time, but **must not be read as a convergence series**
because the campaign changed families.

| Searches | Hours | Findings | Findings/hour | Critical | High | Medium | Low | Adjusted points | Yield/hour |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| S01–S10 | 1.714 | 44 | 25.67 | 9 | 20 | 13 | 2 | 3178.5 | 1854.04 |
| S11–S20 | 4.038 | 42 | 10.40 | 29 | 9 | 4 | 0 | 6570.0 | 1627.05 |
| S21–S30 | 3.743 | 26 | 6.95 | 6 | 13 | 5 | 2 | 1976.0 | 527.95 |
| S31–S40 | 5.116 | 19 | 3.71 | 8 | 9 | 2 | 0 | 4135.0 | 808.22 |
| S41–S41 | 0.855 | 1 | 1.17 | 0 | 1 | 0 | 0 | 50.0 | 58.46 |

## Interpretation and limits

The family-aware result is mixed and more informative than the combined
timeline. Code-execution yield fell substantially within its focused
campaign. Denial-of-service findings became less frequent, but the
weighted yield did not fall because later passes found a concentrated
cluster of critical flaws. Starting a new family or subfamily naturally
raises yield, so a future convergence claim should continue each family
long enough to observe its own trajectory and should never infer progress
from the combined chronological line alone.

The evidence is observational, not a controlled benchmark. Search scope,
models, prompts, target commits and worktree state changed over time.
Finding timestamps are bounded by the producing search rather than
observed exactly, so the denominator uses the complete search duration.
The early F1–F30 composition reconstruction is lower-confidence than the
later retained write-ups. A falling score can also reflect exhausted
search strategies, not only improved code. These limitations make the
score evidence about this review process within its tested threat model,
not proof that the software is secure.

Per-search inputs and results are in `yield-by-search.csv`. Regenerate
both files with:

```sh
python3 adversarial/yield-index/compute_yield.py
```
