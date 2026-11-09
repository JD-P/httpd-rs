#!/usr/bin/env python3
"""Compute adversarial yield from the recovered review index.

Adversarial yield is demonstrated, severity-weighted vulnerability impact per
logical-search hour.  It measures the return from this particular historical
search process; it is not an estimate of the number of bugs remaining or an
absolute security score.

The script writes deterministic CSV and Markdown reports next to the source
index.  It never modifies searches.jsonl or findings.jsonl.
"""

from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import json
import os
from pathlib import Path
from typing import Callable, Iterable


IMPACT_WEIGHTS = {
    "low": 1,
    "medium": 10,
    "high": 100,
    "critical": 1_000,
    "catastrophic": 10_000,
}


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as source:
        return [json.loads(line) for line in source if line.strip()]


def parse_timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def composition_factor(finding: dict) -> float:
    """Halve accessibility for each required unintended behavior.

    The count is a recovered proxy for how many independently wrong behaviors
    an attacker must compose, not a probability.  Keeping this function small
    and explicit makes alternative discounts easy to test.
    """

    count = finding["composition"]["unintended_behavior_count"]
    if not isinstance(count, int) or count < 1:
        raise ValueError(
            f"{finding['claim_id']}: invalid unintended_behavior_count {count!r}"
        )
    return 0.5 ** (count - 1)


def impact_points(finding: dict) -> float:
    try:
        return float(IMPACT_WEIGHTS[finding["impact_tier"]])
    except KeyError as error:
        raise ValueError(
            f"{finding['claim_id']}: unsupported impact tier "
            f"{finding.get('impact_tier')!r}"
        ) from error


def discounted_points(finding: dict) -> float:
    return impact_points(finding) * composition_factor(finding)


def segment_hours(segment: dict) -> float:
    start = parse_timestamp(segment["prompt_timestamp"])
    end = parse_timestamp(segment["ended_at"])
    if end <= start:
        raise ValueError(f"{segment['segment_id']}: non-positive duration")
    return (end - start).total_seconds() / 3_600


def fmt(value: float, digits: int = 2) -> str:
    return f"{value:.{digits}f}"


def percent_change(new: float, old: float) -> float:
    return 100 * (new / old - 1)


def severity_counts(findings: Iterable[dict]) -> collections.Counter:
    return collections.Counter(finding["impact_tier"] for finding in findings)


def summarize(
    search_ids: list[str],
    search_rows: dict[str, dict],
    search_hours: dict[str, float],
    findings_by_search: dict[str, list[dict]],
    score: Callable[[dict], float] = discounted_points,
) -> dict:
    findings = [
        finding
        for search_id in search_ids
        for finding in findings_by_search.get(search_id, [])
    ]
    hours = sum(search_hours[search_id] for search_id in search_ids)
    if hours <= 0:
        raise ValueError("summary has no search time")
    points = sum(score(finding) for finding in findings)
    tiers = severity_counts(findings)
    return {
        "searches": len(search_ids),
        "hours": hours,
        "findings": len(findings),
        "findings_per_hour": len(findings) / hours,
        "low": tiers["low"],
        "medium": tiers["medium"],
        "high": tiers["high"],
        "critical": tiers["critical"],
        "catastrophic": tiers["catastrophic"],
        "points": points,
        "yield": points / hours,
    }


def alternative_score(mode: str) -> Callable[[dict], float]:
    def score(finding: dict) -> float:
        count = finding["composition"]["unintended_behavior_count"]
        if mode == "impact only":
            factor = 1.0
        elif mode == "reciprocal":
            factor = 1 / count
        elif mode == "halving (reported)":
            factor = 0.5 ** (count - 1)
        elif mode == "three-level":
            factor = 1.0 if count == 1 else 0.5 if count == 2 else 0.25
        else:
            raise ValueError(f"unknown sensitivity mode: {mode}")
        return impact_points(finding) * factor

    return score


def write_search_csv(
    path: Path,
    ordered_search_ids: list[str],
    search_rows: dict[str, dict],
    segments: dict[str, dict],
    search_hours: dict[str, float],
    findings_by_search: dict[str, list[dict]],
) -> None:
    fieldnames = [
        "order",
        "search_id",
        "pass_label",
        "started_at",
        "duration_hours",
        "confirmed_findings",
        "findings_per_hour",
        "low",
        "medium",
        "high",
        "critical",
        "catastrophic",
        "impact_points_before_composition",
        "discounted_impact_points",
        "adversarial_yield_per_hour",
    ]
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for order, search_id in enumerate(ordered_search_ids, 1):
            search = search_rows[search_id]
            findings = findings_by_search.get(search_id, [])
            tiers = severity_counts(findings)
            hours = search_hours[search_id]
            started_at = min(
                segments[segment_id]["prompt_timestamp"]
                for segment_id in search["segment_ids"]
            )
            raw_points = sum(impact_points(finding) for finding in findings)
            points = sum(discounted_points(finding) for finding in findings)
            writer.writerow(
                {
                    "order": order,
                    "search_id": search_id,
                    "pass_label": search["pass_label"],
                    "started_at": started_at,
                    "duration_hours": fmt(hours, 6),
                    "confirmed_findings": len(findings),
                    "findings_per_hour": fmt(len(findings) / hours, 6),
                    "low": tiers["low"],
                    "medium": tiers["medium"],
                    "high": tiers["high"],
                    "critical": tiers["critical"],
                    "catastrophic": tiers["catastrophic"],
                    "impact_points_before_composition": fmt(raw_points, 6),
                    "discounted_impact_points": fmt(points, 6),
                    "adversarial_yield_per_hour": fmt(points / hours, 6),
                }
            )


def write_summary(
    path: Path,
    ordered_search_ids: list[str],
    search_rows: dict[str, dict],
    search_hours: dict[str, float],
    findings_by_search: dict[str, list[dict]],
) -> None:
    blocks = [
        ordered_search_ids[index : index + 10]
        for index in range(0, len(ordered_search_ids), 10)
    ]
    block_summaries = [
        summarize(block, search_rows, search_hours, findings_by_search)
        for block in blocks
    ]
    overall = summarize(
        ordered_search_ids, search_rows, search_hours, findings_by_search
    )
    all_findings = [
        finding
        for search_id in ordered_search_ids
        for finding in findings_by_search.get(search_id, [])
    ]
    raw_points = sum(impact_points(finding) for finding in all_findings)
    behavior_counts = collections.Counter(
        finding["composition"]["unintended_behavior_count"]
        for finding in all_findings
    )
    family_names = sorted({finding["primary_family"] for finding in all_findings})

    def family_summary(
        search_ids: list[str],
        family: str,
        score: Callable[[dict], float] = discounted_points,
    ) -> dict:
        matching = {
            search_id: [
                finding
                for finding in findings_by_search.get(search_id, [])
                if finding["primary_family"] == family
            ]
            for search_id in search_ids
        }
        return summarize(search_ids, search_rows, search_hours, matching, score)

    campaigns = []
    for family in ("code_execution", "denial_of_service"):
        search_ids = [
            search_id
            for search_id in ordered_search_ids
            if search_rows[search_id]["requested_focus"] == family
        ]
        midpoint = len(search_ids) // 2
        campaigns.append(
            {
                "family": family,
                "search_ids": search_ids,
                "first_ids": search_ids[:midpoint],
                "last_ids": search_ids[midpoint:],
                "first": family_summary(search_ids[:midpoint], family),
                "last": family_summary(search_ids[midpoint:], family),
            }
        )

    lines = [
        "# Adversarial yield",
        "",
        "> This is a measure of demonstrated vulnerability impact returned by the",
        "> recorded adversarial searches per search-hour. It is not an estimate of",
        "> vulnerabilities remaining and is not an absolute security score.",
        "",
        "## Formula",
        "",
        "For each confirmed finding:",
        "",
        "- impact weights are low `1`, medium `10`, high `100`, critical `1000`,",
        "  and catastrophic `10000`;",
        "- `b` is the recovered number of unintended behaviors that had to compose;",
        "- the composition factor is `2^(1-b)`, halving the contribution for each",
        "  additional required unintended behavior; and",
        "- the finding contributes `impact weight × composition factor` points.",
        "",
        "The reported score is:",
        "",
        "```text",
        "adversarial yield = sum(finding points) / logical-search hours",
        "```",
        "",
        "Only confirmed findings enter the numerator. Duplicate, invalid and",
        "unresolved claims do not. Every completed logical search enters the",
        "denominator, including a search with no confirmed finding. Durations are",
        "the sum of its segment intervals; outage gaps between interrupted and",
        "resumed segments are excluded.",
        "",
        "The decimal scale is meaningful only for comparisons made with the same",
        "formula. Multiplying every impact weight by a constant would change the",
        "number but not the trend.",
        "",
        "## Whole recovered history",
        "",
        "| Search hours | Searches | Confirmed findings | Findings/hour | Raw impact points | Composition-adjusted points | Adversarial yield |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| {fmt(overall['hours'], 3)} | {overall['searches']} | "
            f"{overall['findings']} | {fmt(overall['findings_per_hour'])} | "
            f"{fmt(raw_points, 1)} | {fmt(overall['points'], 1)} | "
            f"**{fmt(overall['yield'])}** |"
        ),
        "",
        "Impact tiers: "
        + ", ".join(
            f"{tier} {overall[tier]}"
            for tier in ("critical", "high", "medium", "low", "catastrophic")
            if overall[tier]
        )
        + ".",
        "",
        "Recovered unintended-behavior counts: "
        + ", ".join(
            f"{count} behaviors: {number} findings"
            for count, number in sorted(behavior_counts.items())
        )
        + ".",
        "",
        "### Contribution by primary family",
        "",
        "These values decompose the whole-history score. They do not compare family",
        "convergence because the time was not allocated uniformly across families.",
        "",
        "| Primary family | Confirmed findings | Adjusted points | Share of points | Points per whole-history hour |",
        "|---|---:|---:|---:|---:|",
    ]
    for family in family_names:
        family_findings = [
            finding
            for finding in all_findings
            if finding["primary_family"] == family
        ]
        family_points = sum(discounted_points(finding) for finding in family_findings)
        lines.append(
            f"| `{family}` | {len(family_findings)} | {fmt(family_points, 1)} | "
            f"{100 * family_points / overall['points']:.1f}% | "
            f"{fmt(family_points / overall['hours'])} |"
        )
    lines.extend(
        [
        "",
        "## Within-family result",
        "",
        "The reviews deliberately changed vulnerability families over time. A simple",
        "chronological total therefore confounds code improvement with the start of a",
        "fresh campaign. The primary convergence comparison uses only searches whose",
        "recovered `requested_focus` explicitly names the outcome family, and compares",
        "the first half with the second half of that family's searches. Broad/general",
        "searches are not assigned to a family after the fact.",
        "",
        "Only findings whose primary family matches the campaign enter its numerator;",
        "all time from the selected searches enters its denominator.",
        "",
        "| Family | Half | Searches | Hours | Matching findings | Findings/hour | Critical | High | Medium | Low | Adjusted points | Yield/hour | Change |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for campaign in campaigns:
        first = campaign["first"]
        last = campaign["last"]
        change = percent_change(last["yield"], first["yield"])
        for half, ids, summary, delta in (
            ("first", campaign["first_ids"], first, "—"),
            ("second", campaign["last_ids"], last, f"{change:+.1f}%"),
        ):
            search_list = ", ".join(ids)
            lines.append(
                f"| `{campaign['family']}` | {half} | {search_list} | "
                f"{fmt(summary['hours'], 3)} | "
                f"{summary['findings']} | {fmt(summary['findings_per_hour'])} | "
                f"{summary['critical']} | {summary['high']} | "
                f"{summary['medium']} | {summary['low']} | "
                f"{fmt(summary['points'], 1)} | {fmt(summary['yield'])} | "
                f"{delta} |"
            )

    rce = campaigns[0]
    dos = campaigns[1]
    rce_raw_change = percent_change(
        rce["last"]["findings_per_hour"], rce["first"]["findings_per_hour"]
    )
    dos_raw_change = percent_change(
        dos["last"]["findings_per_hour"], dos["first"]["findings_per_hour"]
    )
    lines.extend(
        [
            "",
            f"Within the explicitly code-execution-focused searches, matching findings",
            f"per hour changed {rce_raw_change:+.1f}% and severity/composition-adjusted",
            f"yield changed {percent_change(rce['last']['yield'], rce['first']['yield']):+.1f}%.",
            f"Within the explicitly denial-of-service-focused searches, matching",
            f"findings per hour changed {dos_raw_change:+.1f}%, but adjusted yield",
            f"changed {percent_change(dos['last']['yield'], dos['first']['yield']):+.1f}%:",
            "later findings were rarer but more severe. Thus the code-execution",
            "campaign shows convergence on both measures; the denial-of-service",
            "campaign shows lower finding frequency, not lower demonstrated harm per",
            "hour.",
            "",
            "## Sensitivity within focused campaigns",
            "",
            "The impact-tier jumps remain fixed while the composition discount is",
            "varied. The within-family conclusions do not depend on the selected",
            "composition rule.",
            "",
            "| Family | Discount | First half | Second half | Second vs first |",
            "|---|---|---:|---:|---:|",
        ]
    )
    sensitivity_modes = [
        "impact only",
        "reciprocal",
        "halving (reported)",
        "three-level",
    ]
    for campaign in campaigns:
        for mode in sensitivity_modes:
            score = alternative_score(mode)
            first = family_summary(
                campaign["first_ids"], campaign["family"], score
            )
            last = family_summary(campaign["last_ids"], campaign["family"], score)
            lines.append(
                f"| `{campaign['family']}` | {mode} | "
                f"{fmt(first['yield'])} | {fmt(last['yield'])} | "
                f"{percent_change(last['yield'], first['yield']):+.1f}% |"
            )

    lines.extend(
        [
            "",
            "## Cross-family workload history",
            "",
            "For completeness, this is the combined yield in fixed groups of ten",
            "chronological searches (the last has nine). It describes what the review",
            "process found over time, but **must not be read as a convergence series**",
            "because the campaign changed families.",
            "",
            "| Searches | Hours | Findings | Findings/hour | Critical | High | Medium | Low | Adjusted points | Yield/hour |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for block, summary in zip(blocks, block_summaries):
        lines.append(
            f"| {block[0]}–{block[-1]} | {fmt(summary['hours'], 3)} | "
            f"{summary['findings']} | {fmt(summary['findings_per_hour'])} | "
            f"{summary['critical']} | {summary['high']} | "
            f"{summary['medium']} | {summary['low']} | "
            f"{fmt(summary['points'], 1)} | {fmt(summary['yield'])} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation and limits",
            "",
            "The family-aware result is mixed and more informative than the combined",
            "timeline. Code-execution yield fell substantially within its focused",
            "campaign. Denial-of-service findings became less frequent, but the",
            "weighted yield did not fall because later passes found a concentrated",
            "cluster of critical flaws. Starting a new family or subfamily naturally",
            "raises yield, so a future convergence claim should continue each family",
            "long enough to observe its own trajectory and should never infer progress",
            "from the combined chronological line alone.",
            "",
            "The evidence is observational, not a controlled benchmark. Search scope,",
            "models, prompts, target commits and worktree state changed over time.",
            "Finding timestamps are bounded by the producing search rather than",
            "observed exactly, so the denominator uses the complete search duration.",
            "The early F1–F30 composition reconstruction is lower-confidence than the",
            "later retained write-ups. A falling score can also reflect exhausted",
            "search strategies, not only improved code. These limitations make the",
            "score evidence about this review process within its tested threat model,",
            "not proof that the software is secure.",
            "",
            "Per-search inputs and results are in `yield-by-search.csv`. Regenerate",
            "both files with:",
            "",
            "```sh",
            "python3 adversarial/yield-index/compute_yield.py",
            "```",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dir",
        default=os.path.dirname(os.path.abspath(__file__)),
        help="directory containing searches.jsonl and findings.jsonl",
    )
    args = parser.parse_args()
    base = Path(args.dir)

    search_index = load_jsonl(base / "searches.jsonl")
    finding_index = load_jsonl(base / "findings.jsonl")
    search_rows = {
        row["search_id"]: row
        for row in search_index
        if row.get("record_type") == "search"
    }
    segments = {
        row["segment_id"]: row
        for row in search_index
        if row.get("record_type") == "segment"
    }
    confirmed = [
        row for row in finding_index if row.get("disposition") == "confirmed"
    ]
    findings_by_search: dict[str, list[dict]] = collections.defaultdict(list)
    for finding in confirmed:
        findings_by_search[finding["search_id"]].append(finding)

    search_hours = {
        search_id: sum(segment_hours(segments[segment_id]) for segment_id in row["segment_ids"])
        for search_id, row in search_rows.items()
    }
    ordered_search_ids = sorted(
        search_rows,
        key=lambda search_id: min(
            parse_timestamp(segments[segment_id]["prompt_timestamp"])
            for segment_id in search_rows[search_id]["segment_ids"]
        ),
    )

    write_search_csv(
        base / "yield-by-search.csv",
        ordered_search_ids,
        search_rows,
        segments,
        search_hours,
        findings_by_search,
    )
    write_summary(
        base / "yield-summary.md",
        ordered_search_ids,
        search_rows,
        search_hours,
        findings_by_search,
    )
    overall = summarize(
        ordered_search_ids, search_rows, search_hours, findings_by_search
    )
    print(f"searches: {overall['searches']}")
    print(f"search hours: {overall['hours']:.6f}")
    print(f"confirmed findings: {overall['findings']}")
    print(f"composition-adjusted points: {overall['points']:.6f}")
    print(f"adversarial yield: {overall['yield']:.6f} points/search-hour")
    print(f"wrote {base / 'yield-by-search.csv'}")
    print(f"wrote {base / 'yield-summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
