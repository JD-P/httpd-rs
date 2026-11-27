#!/usr/bin/env python3
"""Build a reproducible directive census from an ngxray parser stream.

The input is produced by ngxray's nginx-native tokenizer/parser:

    find EXTRACTED -name '*.conf' -print \
      | nginx_conf_parse - > parsed.json

The accompanying extractor metadata joins each parsed file back to the GitHub
query and repository that discovered it.  No corpus contents are copied into
the output; only aggregate counts and provenance are retained.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence, TextIO


SCHEMA_VERSION = 1

# These queries discover nginx-shaped files through GitHub's language,
# filename, or path metadata rather than by asking for an optional feature.
# Files first found by other queries remain in the expanded stratum only.
NEUTRAL_QUERY_PATTERNS = (
    re.compile(r"^nginx language:Nginx$"),
    re.compile(r'^"server \{" language:Nginx$'),
    re.compile(r"^nginx filename:(?:nginx|default|site|vhost)\.conf$"),
    re.compile(r'^"server \{" filename:(?:nginx|default|site|vhost)\.conf$'),
    re.compile(r"^nginx path:[^ ]+(?: extension:conf)?$"),
    re.compile(r"^nginx path:templates/nginx$"),
)

DIRECTIVE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
COMMAND_BLOCK_RE = re.compile(
    r"(?:static\s+)?ngx_command_t\s+\w+\[\]\s*=\s*\{"
    r"(.*?)ngx_null_command\s*\};",
    re.DOTALL,
)
COMMAND_DECL_RE = re.compile(
    r"(?:static\s+)?ngx_command_t\s+\w+\[\]\s*=", re.DOTALL
)
COMMAND_NAME_RE = re.compile(
    r'\{\s*ngx_string\("([A-Za-z_][A-Za-z0-9_]*)"\)\s*,', re.DOTALL
)

# Families are intentionally overlapping.  They answer “does this config use
# any member of this concern?” rather than partitioning directives.
FAMILY_RULES: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...] = (
    ("routing and URI selection", tuple(map(re.compile, (
        r"^(?:server|location|server_name|listen|try_files|error_page|return|rewrite|if|map|geo)$",
    )))),
    ("static files and indexes", tuple(map(re.compile, (
        r"^(?:root|alias|index|autoindex|open_file_cache.*|aio|directio|sendfile|tcp_nopush)$",
    )))),
    ("HTTP reverse proxy", tuple(map(re.compile, (r"^proxy_", r"^upstream$")))),
    ("FastCGI", (re.compile(r"^fastcgi_"),)),
    ("uWSGI, SCGI, memcached, or gRPC", tuple(map(re.compile, (
        r"^(?:uwsgi|scgi|memcached|grpc)_", r"^(?:uwsgi|scgi|memcached|grpc)_pass$",
    )))),
    ("TLS and certificates", tuple(map(re.compile, (r"^ssl_", r"^ssl$")))),
    ("authentication and authorization", tuple(map(re.compile, (
        r"^(?:allow|deny|auth_.+|satisfy|internal|secure_link.*)$",
    )))),
    ("headers, cookies, and CORS", tuple(map(re.compile, (
        r"^(?:add_header|expires|etag|if_modified_since|headers_more|more_.+|proxy_cookie_.+)$",
    )))),
    ("caching", tuple(map(re.compile, (r"^(?:proxy|fastcgi|uwsgi|scgi)_cache", r"^cache_")))),
    ("compression and transforms", tuple(map(re.compile, (
        r"^(?:gzip|gzip_.+|brotli|brotli_.+|gunzip|sub_filter.*|image_filter.*)$",
    )))),
    ("rate, connection, and request limits", tuple(map(re.compile, (
        r"^(?:limit_req.*|limit_conn.*|client_max_body_size|client_body_timeout|client_header_timeout|send_timeout|keepalive_timeout|lingering_timeout)$",
    )))),
    ("logging and observability", tuple(map(re.compile, (
        r"^(?:access_log|error_log|log_format|open_log_file_cache|stub_status|status_zone)$",
    )))),
    ("HTTP/2, HTTP/3, and QUIC", tuple(map(re.compile, (
        r"^(?:http2|http2_.+|http3|http3_.+|quic_.+)$",
    )))),
    ("stream subsystem", tuple(map(re.compile, (r"^stream$", r"^stream_")))),
    ("mail subsystem", tuple(map(re.compile, (r"^mail$", r"^pop3_", r"^imap_", r"^smtp_")))),
    ("embedded scripting", tuple(map(re.compile, (
        r"^(?:lua_.+|.+_by_lua.*|js_.+|.+_by_js|perl|perl_.+)$",
    )))),
)


@dataclass(frozen=True)
class Provenance:
    repository: str
    query: str
    stratum: str
    extraction_format: str
    extraction_method: str


@dataclass
class Metric:
    occurrences: int = 0
    configs: set[str] | None = None
    repos: set[str] | None = None

    def __post_init__(self) -> None:
        if self.configs is None:
            self.configs = set()
        if self.repos is None:
            self.repos = set()

    def add(self, config: str, repo: str, occurrences: int = 1) -> None:
        self.occurrences += occurrences
        self.configs.add(config)
        if repo:
            self.repos.add(repo)


def query_stratum(query: str) -> str:
    return "neutral" if any(pattern.fullmatch(query) for pattern in NEUTRAL_QUERY_PATTERNS) else "expanded"


def extract_stock_directives_from_text(text: str) -> set[str]:
    names: set[str] = set()
    declarations = COMMAND_DECL_RE.findall(text)
    blocks = COMMAND_BLOCK_RE.findall(text)
    if len(declarations) != len(blocks):
        raise ValueError(
            f"found {len(declarations)} ngx_command_t declarations but parsed {len(blocks)} tables"
        )
    for block in blocks:
        names.update(name.lower() for name in COMMAND_NAME_RE.findall(block))
    return names


def load_stock_directives(source_root: Path) -> dict[str, list[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for path in sorted(source_root.rglob("*.c")):
        relative = str(path.relative_to(source_root))
        text = path.read_text(encoding="utf-8", errors="replace")
        for name in extract_stock_directives_from_text(text):
            result[name].add(relative)
    if not result:
        raise ValueError(f"{source_root}: found no nginx ngx_command_t directive tables")
    return {name: sorted(paths) for name, paths in result.items()}


def load_metadata(path: Path) -> dict[str, Provenance]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected a JSON list")
    result: dict[str, Provenance] = {}
    for entry in raw:
        source = entry.get("source") or {}
        owner = str(source.get("owner") or "")
        repo_name = str(source.get("repo") or "")
        query = str(source.get("query") or "")
        result[str(entry["output_file"])] = Provenance(
            repository=f"{owner}/{repo_name}" if owner and repo_name else "",
            query=query,
            stratum=query_stratum(query),
            extraction_format=str(entry.get("format") or "unknown"),
            extraction_method=str(entry.get("method") or "unknown"),
        )
    return result


def walk_nodes(nodes: Sequence[Mapping[str, object]], parents: tuple[str, ...] = ()) -> Iterator[tuple[str, str]]:
    for node in nodes:
        raw_name = node.get("directive")
        if not isinstance(raw_name, str):
            continue
        name = raw_name.lower()
        if DIRECTIVE_RE.fullmatch(name):
            context = "/".join(parents) if parents else "main"
            yield name, context
        block = node.get("block")
        if isinstance(block, list):
            next_parents = parents + (name,)
            yield from walk_nodes(block, next_parents)


def read_json_stream(stream: TextIO, chunk_size: int = 1024 * 1024) -> Iterator[dict[str, object]]:
    """Decode adjacent JSON values without assuming one physical line each.

    ngxray calls its multi-file output JSONL, but its syntax trees contain
    literal formatting newlines. Values are adjacent JSON objects separated by
    whitespace. Keeping only the unconsumed suffix bounds memory to roughly the
    largest individual configuration AST.
    """
    decoder = json.JSONDecoder()
    buffer = ""
    absolute_offset = 0
    record_number = 0
    eof = False
    while True:
        leading = len(buffer) - len(buffer.lstrip())
        if leading:
            absolute_offset += leading
            buffer = buffer[leading:]
        if not buffer:
            if eof:
                return
            chunk = stream.read(chunk_size)
            if chunk:
                buffer = chunk
                continue
            eof = True
            continue
        try:
            item, end = decoder.raw_decode(buffer)
        except json.JSONDecodeError as error:
            if not eof:
                chunk = stream.read(chunk_size)
                if chunk:
                    buffer += chunk
                    continue
                eof = True
                continue
            raise ValueError(
                f"JSON record {record_number + 1} near character "
                f"{absolute_offset + error.pos}: {error.msg}"
            ) from error
        record_number += 1
        if not isinstance(item, dict):
            raise ValueError(f"JSON record {record_number}: expected an object")
        yield item
        absolute_offset += end
        buffer = buffer[end:]


def percent(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 4) if whole else 0.0


def metric_row(name: str, metrics: Mapping[str, Metric], totals: Mapping[str, dict[str, set[str]]]) -> dict[str, object]:
    all_metric = metrics.get("all", Metric())
    neutral_metric = metrics.get("neutral", Metric())
    return {
        "name": name,
        "occurrences": all_metric.occurrences,
        "config_count": len(all_metric.configs),
        "config_percent": percent(len(all_metric.configs), len(totals["all"]["configs"])),
        "repository_count_observed": len(all_metric.repos),
        "repository_percent_of_observed": percent(len(all_metric.repos), len(totals["all"]["repos"])),
        "neutral_occurrences": neutral_metric.occurrences,
        "neutral_config_count": len(neutral_metric.configs),
        "neutral_config_percent": percent(len(neutral_metric.configs), len(totals["neutral"]["configs"])),
        "neutral_repository_count_observed": len(neutral_metric.repos),
        "neutral_repository_percent_of_observed": percent(len(neutral_metric.repos), len(totals["neutral"]["repos"])),
    }


def census(
    items: Iterable[dict[str, object]],
    metadata: Mapping[str, Provenance],
    stock_directives: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, object]:
    stock_directives = stock_directives or {}
    directive_metrics: dict[str, dict[str, Metric]] = defaultdict(dict)
    context_metrics: dict[str, dict[str, Metric]] = defaultdict(dict)
    family_metrics: dict[str, dict[str, Metric]] = defaultdict(dict)
    totals = {
        "all": {"configs": set(), "repos": set()},
        "neutral": {"configs": set(), "repos": set()},
    }
    extraction_formats: Counter[str] = Counter()
    extraction_methods: Counter[str] = Counter()
    query_counts: Counter[str] = Counter()
    parse_failures = 0
    missing_metadata = 0

    def add_metric(bucket: dict[str, Metric], stratum: str, config: str, repo: str, count: int = 1) -> None:
        bucket.setdefault("all", Metric()).add(config, repo, count)
        if stratum == "neutral":
            bucket.setdefault("neutral", Metric()).add(config, repo, count)

    for item in items:
        file_value = item.get("file")
        if not isinstance(file_value, str):
            missing_metadata += 1
            continue
        config_id = Path(file_value).name
        provenance = metadata.get(config_id)
        if provenance is None:
            missing_metadata += 1
            provenance = Provenance("", "", "expanded", "unknown", "unknown")
        if item.get("error") is True:
            parse_failures += 1
            continue
        nodes = item.get("config")
        if not isinstance(nodes, list):
            parse_failures += 1
            continue

        totals["all"]["configs"].add(config_id)
        if provenance.repository:
            totals["all"]["repos"].add(provenance.repository)
        if provenance.stratum == "neutral":
            totals["neutral"]["configs"].add(config_id)
            if provenance.repository:
                totals["neutral"]["repos"].add(provenance.repository)
        extraction_formats[provenance.extraction_format] += 1
        extraction_methods[provenance.extraction_method] += 1
        query_counts[provenance.query] += 1

        directives: Counter[str] = Counter()
        contexts: Counter[str] = Counter()
        for directive, context in walk_nodes(nodes):
            directives[directive] += 1
            contexts[f"{context}:{directive}"] += 1
        for directive, count in directives.items():
            add_metric(directive_metrics[directive], provenance.stratum, config_id, provenance.repository, count)
        for context, count in contexts.items():
            add_metric(context_metrics[context], provenance.stratum, config_id, provenance.repository, count)

        for family, patterns in FAMILY_RULES:
            count = sum(n for directive, n in directives.items() if any(pattern.search(directive) for pattern in patterns))
            if count:
                add_metric(family_metrics[family], provenance.stratum, config_id, provenance.repository, count)

    directives = [metric_row(name, values, totals) for name, values in directive_metrics.items()]
    for row in directives:
        name = str(row["name"])
        sources = stock_directives.get(name, ())
        row["classification"] = "stock nginx directive" if sources else "non-stock statement head"
        row["stock_source_files"] = ";".join(sources)
    directives.sort(key=lambda row: (-int(row["config_count"]), str(row["name"])))
    contexts = [metric_row(name, values, totals) for name, values in context_metrics.items()]
    contexts.sort(key=lambda row: (-int(row["config_count"]), str(row["name"])))
    families = [metric_row(name, values, totals) for name, values in family_metrics.items()]
    families.sort(key=lambda row: (-int(row["config_count"]), str(row["name"])))
    stock_inventory = []
    for name, sources in stock_directives.items():
        row = metric_row(name, directive_metrics.get(name, {}), totals)
        row["classification"] = "stock nginx directive"
        row["stock_source_files"] = ";".join(sources)
        stock_inventory.append(row)
    stock_inventory.sort(key=lambda row: (-int(row["config_count"]), str(row["name"])))
    source_to_directives: dict[str, set[str]] = defaultdict(set)
    for name, sources in stock_directives.items():
        for source in sources:
            source_to_directives[source].add(name)
    observed_names = {str(row["name"]) for row in stock_inventory if row["config_count"]}
    stock_source_inventory = []
    for source, names in source_to_directives.items():
        observed = sorted(names & observed_names)
        unobserved = sorted(names - observed_names)
        stock_source_inventory.append({
            "source_file": source,
            "directive_count": len(names),
            "directive_names_observed_any_context": len(observed),
            "directives": ";".join(sorted(names)),
            "unobserved_directives": ";".join(unobserved),
        })
    stock_source_inventory.sort(
        key=lambda row: (-int(row["directive_count"]), str(row["source_file"]))
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "population": {
            "parseable_unique_configs": len(totals["all"]["configs"]),
            "repositories_observed_after_content_deduplication": len(totals["all"]["repos"]),
            "neutral_parseable_unique_configs": len(totals["neutral"]["configs"]),
            "neutral_repositories_observed_after_content_deduplication": len(totals["neutral"]["repos"]),
            "parse_failures": parse_failures,
            "records_missing_metadata": missing_metadata,
            "stock_source_directives": len(stock_inventory),
            "observed_stock_directives": sum(1 for row in stock_inventory if row["config_count"]),
            "observed_non_stock_statement_heads": sum(
                1 for row in directives if row["classification"] == "non-stock statement head"
            ),
            "stock_source_files_with_command_tables": len(stock_source_inventory),
        },
        "directives": directives,
        "stock_directive_inventory": stock_inventory,
        "stock_source_inventory": stock_source_inventory,
        "contexts": contexts,
        "families": families,
        "extraction_formats": dict(extraction_formats.most_common()),
        "extraction_methods": dict(extraction_methods.most_common()),
        "discovery_queries": dict(query_counts.most_common()),
    }


CSV_COLUMNS = (
    "name",
    "classification",
    "stock_source_files",
    "occurrences",
    "config_count",
    "config_percent",
    "repository_count_observed",
    "repository_percent_of_observed",
    "neutral_occurrences",
    "neutral_config_count",
    "neutral_config_percent",
    "neutral_repository_count_observed",
    "neutral_repository_percent_of_observed",
)


def write_csv(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_source_inventory_csv(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    columns = (
        "source_file",
        "directive_count",
        "directive_names_observed_any_context",
        "directives",
        "unobserved_directives",
    )
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def render_table(rows: Sequence[Mapping[str, object]], limit: int | None = None) -> str:
    selected = rows if limit is None else rows[:limit]
    lines = [
        "| Name | Unique configs | Config % | Neutral configs | Neutral % | Occurrences |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in selected:
        name = str(row["name"]).replace("|", "\\|")
        lines.append(
            f"| `{name}` | {row['config_count']:,} | {row['config_percent']:.2f}% | "
            f"{row['neutral_config_count']:,} | {row['neutral_config_percent']:.2f}% | {row['occurrences']:,} |"
        )
    return "\n".join(lines)


def render_directive_table(rows: Sequence[Mapping[str, object]], limit: int = 100) -> str:
    lines = [
        "| Statement head | Class | Unique configs | Config % | Neutral configs | Neutral % | Occurrences |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows[:limit]:
        name = str(row["name"]).replace("|", "\\|")
        classification = str(row.get("classification") or "").replace("|", "\\|")
        lines.append(
            f"| `{name}` | {classification} | {row['config_count']:,} | {row['config_percent']:.2f}% | "
            f"{row['neutral_config_count']:,} | {row['neutral_config_percent']:.2f}% | {row['occurrences']:,} |"
        )
    return "\n".join(lines)


def render_markdown(result: Mapping[str, object], manifest: Mapping[str, object]) -> str:
    population = result["population"]
    directives = result["directives"]
    families = result["families"]
    return f"""<!-- Generated by tools/nginx_corpus_census.py; do not edit by hand. -->

# nginx configuration corpus census

This is a descriptive census of unique, token-parseable nginx configuration
texts found by the pinned GitHub Code Search collection manifest. It is
evidence for compatibility prioritization, not an estimate of all deployed
nginx servers.

The method reconstructs the public
[ngxray corpus](https://github.com/califio/ngxray) described in
[“Needle in a haystack”](https://blog.calif.io/p/needle-in-a-haystack-measuring-the).
The original authors reported 35,633 parseable configurations but did not
publish the downloaded corpus, so this table is a fresh collection using their
pinned 102-query collector rather than a claim to contain the same files.

## Population

- Collection date: {manifest.get('collected_at', 'unknown')}
- Collector: `{manifest.get('collector_commit', 'unknown')}`
- nginx tokenizer: `{manifest.get('nginx_commit', 'unknown')}`
- Content-unique raw candidates: {manifest.get('raw_unique_files', 0):,}
- Content-unique normalized extracts: {manifest.get('extracted_unique_configs', 0):,}
- Parseable unique extracted configs: {population['parseable_unique_configs']:,}
- Parse failures after extraction: {population['parse_failures']:,}
- Neutral-discovery configs: {population['neutral_parseable_unique_configs']:,}
- Repositories represented after content deduplication: {population['repositories_observed_after_content_deduplication']:,}
- Stock nginx directives enumerated from source: {population['stock_source_directives']:,}
- Stock nginx directives observed at least once: {population['observed_stock_directives']:,}
- Non-stock statement heads observed: {population['observed_non_stock_statement_heads']:,}
- nginx source files containing command tables: {population['stock_source_files_with_command_tables']:,}

The collector deduplicates equal content before extraction. Consequently,
repository counts undercount copied stock configurations and are not used as
the primary ranking. GitHub Code Search exposes at most 1,000 results per
query, and the query union deliberately includes feature-targeted searches.
The **neutral** columns are a less-biased sensitivity view containing files
first found through language, filename, path, or structural `server {{`
queries. Neither view is a probability sample.

## Directive-name family prevalence

Families are a heuristic grouping of statement heads and overlap: one
configuration may contribute to several rows. They are not semantic feature
detection. In particular, modes encoded as arguments (for example legacy
`listen ... http2`) are not counted in the HTTP/2 row unless an HTTP/2-family
directive also occurs. Use the directive and context tables for exact claims.

{render_table(families)}

## Directive prevalence

The 100 most prevalent directives are shown here. The complete table is in
[`nginx-directive-frequency.csv`](nginx-directive-frequency.csv), with an
alternate ordering by the neutral sensitivity view in
[`nginx-directive-frequency-neutral.csv`](nginx-directive-frequency-neutral.csv),
and exact counts also available in
[`nginx-corpus-census.json`](nginx-corpus-census.json).

The parser records every statement head, including data rows inside blocks
such as `map`. The **Class** column distinguishes names present in a pinned
stock nginx `ngx_command_t` table from non-stock statement heads. The latter
category includes both third-party module directives and block-specific data;
the complete
[`nginx-context-frequency.csv`](nginx-context-frequency.csv) table
disambiguates them. The exhaustive stock-source inventory,
including directives not observed at all, is
[`nginx-stock-directive-inventory.csv`](nginx-stock-directive-inventory.csv).
The same exhaustive inventory grouped by nginx source file is
[`nginx-stock-source-inventory.csv`](nginx-stock-source-inventory.csv), so an
entire module cannot disappear merely because none of its directives occurred
in the sample. Its observed-name count is lexical: a shared name such as
`server` appearing in an HTTP context does not prove that the mail or stream
module using the same name occurred.

{render_directive_table(directives, 100)}

## Interpretation rules

1. Use config prevalence to choose which nginx features deserve compiler and
   migration support first.
2. Check the neutral and expanded columns together. A large expanded-only
   value may be an artifact of a directive-targeted discovery query.
3. Do not interpret repository percentages as deployment market share.
4. “Parseable” means accepted by nginx's tokenizer and block grammar. The
   parser intentionally records unknown directives instead of loading every
   nginx module, so it does not certify that a stock nginx binary would accept
   the entire file.
5. Templates are normalized before parsing. Their counts describe intended
   configurations, not necessarily a rendered production file.

## Reproduce

The corpus is deliberately not committed. Given a read-only GitHub token, the
runner resumes collection state in a caller-selected working directory and
regenerates every aggregate artifact:

```sh
GH_TOKEN=... tools/run_nginx_corpus_census.sh /large/work/directory docs
```

GitHub search results change over time. Reproduction means rebuilding with the
same collector, queries, extraction rules, tokenizer, and aggregation method;
it does not mean that GitHub will return the same snapshot indefinitely.
"""


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_result(result: Mapping[str, object]) -> None:
    population = result["population"]
    total_configs = int(population["parseable_unique_configs"])
    neutral_configs = int(population["neutral_parseable_unique_configs"])
    for section in ("directives", "contexts", "families", "stock_directive_inventory"):
        rows = result[section]
        names: set[str] = set()
        for row in rows:
            name = str(row["name"])
            if name in names:
                raise ValueError(f"duplicate {section} row: {name}")
            names.add(name)
            config_count = int(row["config_count"])
            neutral_count = int(row["neutral_config_count"])
            if not 0 <= neutral_count <= config_count <= total_configs:
                raise ValueError(f"invalid {section} config counts for {name}")
            if neutral_count > neutral_configs:
                raise ValueError(f"invalid {section} neutral count for {name}")
    if len(result["stock_directive_inventory"]) != int(population["stock_source_directives"]):
        raise ValueError("stock directive inventory count disagrees with population")
    observed_stock = sum(
        1 for row in result["stock_directive_inventory"] if int(row["config_count"]) > 0
    )
    if observed_stock != int(population["observed_stock_directives"]):
        raise ValueError("observed stock directive count disagrees with population")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parser-json", "--jsonl", dest="parser_json", type=Path, required=True,
                        help="ngxray concatenated JSON object stream")
    parser.add_argument("--metadata", type=Path, required=True, help="extractor metadata.json")
    parser.add_argument("--manifest", type=Path, required=True, help="collection manifest JSON")
    parser.add_argument("--nginx-source", type=Path, required=True,
                        help="pinned nginx src/ tree used to enumerate stock directives")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    metadata = load_metadata(args.metadata)
    stock_directives = load_stock_directives(args.nginx_source)
    with args.parser_json.open(encoding="utf-8") as stream:
        result = census(read_json_stream(stream), metadata, stock_directives)
    validate_result(result)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    result["provenance"] = {
        **manifest,
        "parser_json_sha256": file_sha256(args.parser_json),
        "extractor_metadata_sha256": file_sha256(args.metadata),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "nginx-corpus-census.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_csv(args.output_dir / "nginx-directive-frequency.csv", result["directives"])
    write_csv(
        args.output_dir / "nginx-directive-frequency-neutral.csv",
        sorted(
            result["directives"],
            key=lambda row: (-int(row["neutral_config_count"]), str(row["name"])),
        ),
    )
    write_csv(args.output_dir / "nginx-context-frequency.csv", result["contexts"])
    write_csv(args.output_dir / "nginx-feature-family-frequency.csv", result["families"])
    write_csv(args.output_dir / "nginx-stock-directive-inventory.csv", result["stock_directive_inventory"])
    write_source_inventory_csv(
        args.output_dir / "nginx-stock-source-inventory.csv", result["stock_source_inventory"]
    )
    (args.output_dir / "nginx-corpus-census.md").write_text(
        render_markdown(result, manifest), encoding="utf-8"
    )
    print(json.dumps(result["population"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
