#!/usr/bin/env python3
"""Render adversarial yield by primary vulnerability family.

The whole-history family yield is an additive decomposition of the reported
adversarial yield: each family's adjusted finding points are divided by all
recorded logical-search hours. This is deliberately not presented as search
efficiency because most searches were broad or mixed rather than allocated to
one outcome family.

The script writes deterministic PNG/SVG charts plus matching CSV and Markdown
tables. It never modifies the source JSONL indexes.
"""

from __future__ import annotations

import argparse
import collections
import csv
import os
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
matplotlib.rcParams.update(
    {
        "axes.spines.right": False,
        "axes.spines.top": False,
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "svg.hashsalt": "httpd-rs-adversarial-family-yield",
    }
)
from matplotlib import pyplot as plt  # noqa: E402

from compute_yield import (  # noqa: E402
    discounted_points,
    impact_points,
    load_jsonl,
    parse_timestamp,
    segment_hours,
)


TRACKED_FAMILIES = (
    "code_execution",
    "authority_bypass",
    "information_disclosure",
    "integrity_violation",
    "server_request_abuse",
    "protocol_confusion",
    "cryptographic_trust_failure",
    "denial_of_service",
    "memory_safety",
)
REPORT_FAMILIES = TRACKED_FAMILIES + ("unclassified",)
SEVERITIES = ("catastrophic", "critical", "high", "medium", "low")
DISPLAY_NAMES = {
    "code_execution": "Code execution",
    "authority_bypass": "Authority bypass",
    "information_disclosure": "Information disclosure",
    "integrity_violation": "Integrity violation",
    "server_request_abuse": "Server request abuse",
    "protocol_confusion": "Protocol confusion",
    "cryptographic_trust_failure": "Cryptographic trust failure",
    "denial_of_service": "Denial of service",
    "memory_safety": "Memory safety",
    "unclassified": "Unclassified (escape hatch)",
}
COLORS = {
    "code_execution": "#D55E00",
    "authority_bypass": "#CC79A7",
    "information_disclosure": "#0072B2",
    "integrity_violation": "#009E73",
    "server_request_abuse": "#56B4E9",
    "protocol_confusion": "#B79F00",
    "cryptographic_trust_failure": "#6F4E7C",
    "denial_of_service": "#E69F00",
    "memory_safety": "#222222",
    "unclassified": "#999999",
}


def fmt(value: float, digits: int = 2) -> str:
    return f"{value:.{digits}f}"


def markdown_number(value: float, digits: int = 2) -> str:
    return f"{value:,.{digits}f}"


def load_report_data(base: Path) -> dict:
    search_index = load_jsonl(base / "searches.jsonl")
    finding_index = load_jsonl(base / "findings.jsonl")
    searches = {
        row["search_id"]: row
        for row in search_index
        if row.get("record_type") == "search"
    }
    segments = {
        row["segment_id"]: row
        for row in search_index
        if row.get("record_type") == "segment"
    }
    search_hours = {
        search_id: sum(
            segment_hours(segments[segment_id])
            for segment_id in row["segment_ids"]
        )
        for search_id, row in searches.items()
    }
    ordered_search_ids = sorted(
        searches,
        key=lambda search_id: min(
            parse_timestamp(segments[segment_id]["prompt_timestamp"])
            for segment_id in searches[search_id]["segment_ids"]
        ),
    )
    confirmed = [
        row for row in finding_index if row.get("disposition") == "confirmed"
    ]
    unknown = sorted(
        {finding["primary_family"] for finding in confirmed}
        - set(REPORT_FAMILIES)
    )
    if unknown:
        raise ValueError(f"unknown primary vulnerability families: {unknown}")
    findings_by_search: dict[str, list[dict]] = collections.defaultdict(list)
    for finding in confirmed:
        findings_by_search[finding["search_id"]].append(finding)

    total_hours = sum(search_hours.values())
    total_adjusted_points = sum(discounted_points(finding) for finding in confirmed)
    families = []
    for family in REPORT_FAMILIES:
        findings = [
            finding
            for finding in confirmed
            if finding["primary_family"] == family
        ]
        tiers = collections.Counter(
            finding["impact_tier"] for finding in findings
        )
        raw_points = sum(impact_points(finding) for finding in findings)
        adjusted_points = sum(discounted_points(finding) for finding in findings)
        dedicated_search_ids = [
            search_id
            for search_id in ordered_search_ids
            if searches[search_id].get("requested_focus") == family
        ]
        dedicated_hours = sum(
            search_hours[search_id] for search_id in dedicated_search_ids
        )
        dedicated_findings = [
            finding
            for search_id in dedicated_search_ids
            for finding in findings_by_search.get(search_id, [])
            if finding["primary_family"] == family
        ]
        dedicated_points = sum(
            discounted_points(finding) for finding in dedicated_findings
        )
        families.append(
            {
                "family": family,
                "tracked_family": family != "unclassified",
                "confirmed_findings": len(findings),
                **{severity: tiers[severity] for severity in SEVERITIES},
                "raw_points": raw_points,
                "adjusted_points": adjusted_points,
                "share_of_adjusted_points": (
                    adjusted_points / total_adjusted_points
                    if total_adjusted_points
                    else 0.0
                ),
                "findings_per_all_search_hour": len(findings) / total_hours,
                "adjusted_yield_per_all_search_hour": adjusted_points / total_hours,
                "dedicated_searches": len(dedicated_search_ids),
                "dedicated_hours": dedicated_hours,
                "dedicated_matching_findings": len(dedicated_findings),
                "dedicated_adjusted_points": dedicated_points,
                "dedicated_adjusted_yield": (
                    dedicated_points / dedicated_hours if dedicated_hours else None
                ),
            }
        )

    blocks = []
    for block_order, start in enumerate(range(0, len(ordered_search_ids), 10), 1):
        search_ids = ordered_search_ids[start : start + 10]
        hours = sum(search_hours[search_id] for search_id in search_ids)
        family_rows = []
        for family in REPORT_FAMILIES:
            findings = [
                finding
                for search_id in search_ids
                for finding in findings_by_search.get(search_id, [])
                if finding["primary_family"] == family
            ]
            points = sum(discounted_points(finding) for finding in findings)
            family_rows.append(
                {
                    "family": family,
                    "confirmed_findings": len(findings),
                    "adjusted_points": points,
                    "adjusted_yield": points / hours,
                }
            )
        blocks.append(
            {
                "block_order": block_order,
                "first_search": search_ids[0],
                "last_search": search_ids[-1],
                "searches": len(search_ids),
                "hours": hours,
                "families": family_rows,
                "total_adjusted_yield": sum(
                    row["adjusted_yield"] for row in family_rows
                ),
            }
        )

    return {
        "searches": len(searches),
        "hours": total_hours,
        "confirmed_findings": len(confirmed),
        "adjusted_points": total_adjusted_points,
        "adjusted_yield": total_adjusted_points / total_hours,
        "families": families,
        "blocks": blocks,
    }


def write_family_csv(path: Path, report: dict) -> None:
    fieldnames = [
        "family",
        "tracked_family",
        "confirmed_findings",
        *SEVERITIES,
        "raw_points",
        "adjusted_points",
        "share_of_adjusted_points",
        "findings_per_all_search_hour",
        "adjusted_yield_per_all_search_hour",
        "dedicated_searches",
        "dedicated_hours",
        "dedicated_matching_findings",
        "dedicated_adjusted_points",
        "dedicated_adjusted_yield",
    ]
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in report["families"]:
            serialized = dict(row)
            for field in (
                "raw_points",
                "adjusted_points",
                "share_of_adjusted_points",
                "findings_per_all_search_hour",
                "adjusted_yield_per_all_search_hour",
                "dedicated_hours",
                "dedicated_adjusted_points",
            ):
                serialized[field] = fmt(serialized[field], 6)
            serialized["dedicated_adjusted_yield"] = (
                ""
                if serialized["dedicated_adjusted_yield"] is None
                else fmt(serialized["dedicated_adjusted_yield"], 6)
            )
            writer.writerow(serialized)


def write_block_csv(path: Path, report: dict) -> None:
    fieldnames = [
        "block_order",
        "first_search",
        "last_search",
        "searches",
        "hours",
        "family",
        "confirmed_findings",
        "adjusted_points",
        "adjusted_yield",
        "total_adjusted_yield",
    ]
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for block in report["blocks"]:
            for family in block["families"]:
                writer.writerow(
                    {
                        "block_order": block["block_order"],
                        "first_search": block["first_search"],
                        "last_search": block["last_search"],
                        "searches": block["searches"],
                        "hours": fmt(block["hours"], 6),
                        "family": family["family"],
                        "confirmed_findings": family["confirmed_findings"],
                        "adjusted_points": fmt(family["adjusted_points"], 6),
                        "adjusted_yield": fmt(family["adjusted_yield"], 6),
                        "total_adjusted_yield": fmt(
                            block["total_adjusted_yield"], 6
                        ),
                    }
                )


def write_markdown(path: Path, report: dict) -> None:
    ranked = sorted(
        report["families"],
        key=lambda row: (
            -row["adjusted_yield_per_all_search_hour"],
            REPORT_FAMILIES.index(row["family"]),
        ),
    )
    lines = [
        "# Adversarial yield by vulnerability family",
        "",
        "![Adversarial yield by primary vulnerability family](yield-by-family.png)",
        "",
        "[Scalable SVG version](yield-by-family.svg)",
        "",
        "> Family yield here is an additive decomposition of the whole-history",
        "> score. Each family's adjusted finding points are divided by all recorded",
        "> logical-search hours. It measures contribution to observed historical",
        "> yield, not family-specific search efficiency or vulnerabilities remaining.",
        "",
        "Only unique confirmed findings enter the numerator. Impact weights and the",
        "composition discount are defined in",
        "[`../vulnerability-families.md`](../vulnerability-families.md).",
        "`unclassified` is shown for completeness but is an escape hatch rather than",
        "one of the nine tracked vulnerability families.",
        "",
        "## Whole-history contribution",
        "",
        (
            f"The index contains {report['confirmed_findings']} confirmed findings "
            f"and {markdown_number(report['adjusted_points'], 1)} adjusted points "
            f"over {markdown_number(report['hours'], 3)} search-hours, for "
            f"{markdown_number(report['adjusted_yield'])} adjusted points/hour."
        ),
        "",
        "| Primary family | Confirmed | Findings/all h | Raw points | Adjusted points | Share | Adjusted points/all h |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in ranked:
        lines.append(
            f"| `{row['family']}` | {row['confirmed_findings']} | "
            f"{fmt(row['findings_per_all_search_hour'])} | "
            f"{markdown_number(row['raw_points'], 1)} | "
            f"{markdown_number(row['adjusted_points'], 1)} | "
            f"{100 * row['share_of_adjusted_points']:.1f}% | "
            f"**{markdown_number(row['adjusted_yield_per_all_search_hour'])}** |"
        )
    lines.extend(
        [
            "",
            "## Severity distribution",
            "",
            "| Primary family | Catastrophic | Critical | High | Medium | Low |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in ranked:
        lines.append(
            f"| `{row['family']}` | {row['catastrophic']} | {row['critical']} | "
            f"{row['high']} | {row['medium']} | {row['low']} |"
        )
    lines.extend(
        [
            "",
            "## Dedicated-search context",
            "",
            "Only searches whose recovered `requested_focus` exactly names the family",
            "appear here. General, mixed, PCRE2, regression, and static-hosting",
            "searches are not assigned after the fact. A dash therefore means that the",
            "index does not support a family-specific efficiency estimate.",
            "",
            "| Primary family | Dedicated searches | Hours | Matching findings | Adjusted points | Adjusted yield/hour |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in ranked:
        dedicated_yield = row["dedicated_adjusted_yield"]
        lines.append(
            f"| `{row['family']}` | {row['dedicated_searches']} | "
            f"{markdown_number(row['dedicated_hours'], 3)} | "
            f"{row['dedicated_matching_findings']} | "
            f"{markdown_number(row['dedicated_adjusted_points'], 1)} | "
            f"{'—' if dedicated_yield is None else markdown_number(dedicated_yield)} |"
        )

    nonzero_families = [
        family
        for family in REPORT_FAMILIES
        if any(
            next(
                row["adjusted_yield"]
                for row in block["families"]
                if row["family"] == family
            )
            > 0
            for block in report["blocks"]
        )
    ]
    lines.extend(
        [
            "",
            "## Chronological family yield",
            "",
            "Each row is a fixed chronological block of ten logical searches (the",
            "last may be shorter). Values are adjusted points divided by that block's",
            "hours and sum to the total column. Campaign focus changed over time, so",
            "this table describes workload history rather than controlled convergence.",
            "",
            "| Searches | Hours | "
            + " | ".join(f"`{family}`" for family in nonzero_families)
            + " | Total |",
            "|---|---:|"
            + "---:|" * len(nonzero_families)
            + "---:|",
        ]
    )
    for block in report["blocks"]:
        by_family = {row["family"]: row for row in block["families"]}
        lines.append(
            f"| {block['first_search']}–{block['last_search']} | "
            f"{markdown_number(block['hours'], 3)} | "
            + " | ".join(
                markdown_number(by_family[family]["adjusted_yield"])
                for family in nonzero_families
            )
            + f" | **{markdown_number(block['total_adjusted_yield'])}** |"
        )
    lines.extend(
        [
            "",
            "## Reproduce",
            "",
            "```sh",
            "python3 adversarial/yield-index/plot_family_yield.py",
            "```",
            "",
            "The matching machine-readable tables are `yield-by-family.csv` and",
            "`yield-by-family-block.csv`.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def render_figure(png_path: Path, svg_path: Path, report: dict) -> None:
    ranked = sorted(
        report["families"],
        key=lambda row: (
            row["adjusted_yield_per_all_search_hour"],
            -REPORT_FAMILIES.index(row["family"]),
        ),
    )
    fig, (family_ax, time_ax) = plt.subplots(
        2,
        1,
        figsize=(15, 12),
        gridspec_kw={"height_ratios": (1.2, 1.0)},
        layout="constrained",
    )
    fig.suptitle(
        "httpd-rs adversarial yield by primary vulnerability family",
        fontsize=18,
        fontweight="bold",
    )

    labels = [DISPLAY_NAMES[row["family"]] for row in ranked]
    values = [row["adjusted_yield_per_all_search_hour"] for row in ranked]
    colors = [COLORS[row["family"]] for row in ranked]
    bars = family_ax.barh(labels, values, color=colors, edgecolor="white", linewidth=0.7)
    max_value = max(values) if values else 1.0
    family_ax.set_xlim(0, max_value * 1.24)
    family_ax.set_xlabel("Composition-adjusted impact points per all search-hours")
    family_ax.set_title(
        "A. Whole-history yield contribution (additive across families)",
        loc="left",
        fontweight="bold",
    )
    family_ax.grid(axis="x", color="#dddddd", linewidth=0.8)
    family_ax.set_axisbelow(True)
    for bar, row, value in zip(bars, ranked, values):
        annotation = f"{value:,.2f}  ({row['confirmed_findings']} findings)"
        family_ax.text(
            value + max_value * 0.012,
            bar.get_y() + bar.get_height() / 2,
            annotation,
            va="center",
            fontsize=9,
        )

    block_labels = [
        f"{block['first_search']}–{block['last_search']}"
        for block in report["blocks"]
    ]
    bottom = [0.0] * len(report["blocks"])
    for family in REPORT_FAMILIES:
        values = [
            next(
                row["adjusted_yield"]
                for row in block["families"]
                if row["family"] == family
            )
            for block in report["blocks"]
        ]
        if not any(values):
            continue
        time_ax.bar(
            block_labels,
            values,
            bottom=bottom,
            color=COLORS[family],
            edgecolor="white",
            linewidth=0.5,
            label=DISPLAY_NAMES[family],
        )
        bottom = [old + new for old, new in zip(bottom, values)]
    time_ax.plot(
        block_labels,
        [block["total_adjusted_yield"] for block in report["blocks"]],
        color="#111111",
        marker="o",
        linewidth=1.5,
        label="Total",
        zorder=5,
    )
    time_ax.set_ylabel("Adjusted points/hour within chronological block")
    time_ax.set_xlabel("Chronological logical-search blocks")
    time_ax.set_title(
        "B. Family composition of historical yield (campaign focus changed)",
        loc="left",
        fontweight="bold",
    )
    time_ax.grid(axis="y", color="#dddddd", linewidth=0.8)
    time_ax.set_axisbelow(True)
    time_ax.legend(
        loc="upper right",
        ncol=3,
        frameon=True,
        framealpha=0.92,
    )
    fig.savefig(
        png_path,
        dpi=180,
        metadata={"Software": "httpd-rs adversarial yield report"},
    )
    fig.savefig(
        svg_path,
        metadata={
            "Creator": "httpd-rs adversarial yield report",
            "Date": None,
        },
    )
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dir",
        default=os.path.dirname(os.path.abspath(__file__)),
        help="directory containing searches.jsonl and findings.jsonl",
    )
    parser.add_argument(
        "--output-dir",
        help="output directory (defaults to --dir)",
    )
    args = parser.parse_args()
    base = Path(args.dir)
    output = Path(args.output_dir) if args.output_dir else base
    output.mkdir(parents=True, exist_ok=True)

    report = load_report_data(base)
    outputs = {
        "family_csv": output / "yield-by-family.csv",
        "block_csv": output / "yield-by-family-block.csv",
        "markdown": output / "yield-by-family.md",
        "png": output / "yield-by-family.png",
        "svg": output / "yield-by-family.svg",
    }
    write_family_csv(outputs["family_csv"], report)
    write_block_csv(outputs["block_csv"], report)
    write_markdown(outputs["markdown"], report)
    render_figure(outputs["png"], outputs["svg"], report)

    print(f"searches: {report['searches']}")
    print(f"search hours: {report['hours']:.6f}")
    print(f"confirmed findings: {report['confirmed_findings']}")
    print(f"adversarial yield: {report['adjusted_yield']:.6f} points/search-hour")
    for path in outputs.values():
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
