#!/bin/sh
# Rebuild the public-nginx-config census without copying corpus files into git.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 WORK_DIRECTORY [OUTPUT_DIRECTORY]" >&2
    exit 2
fi

if [ -z "${GITHUB_TOKEN:-${GH_TOKEN:-}}" ]; then
    echo "GITHUB_TOKEN or GH_TOKEN is required for GitHub Code Search" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
work_dir=$1
output_dir=${2:-"$repo_root/docs"}
ngxray_dir="$work_dir/ngxray"
corpus_dir="$work_dir/corpus"
venv_dir="$work_dir/venv"

ngxray_commit=fa4cc4a1e6a0bb58cf1af86a5ef7180783d1bd98
nginx_commit=d44205284fa41662da803b796d6056fc1e59b1f3
collector_target=45000

mkdir -p "$work_dir" "$output_dir"

if [ ! -d "$ngxray_dir/.git" ]; then
    git clone https://github.com/califio/ngxray.git "$ngxray_dir"
fi
git -C "$ngxray_dir" fetch --depth 1 origin "$ngxray_commit"
git -C "$ngxray_dir" checkout --detach "$ngxray_commit"

# The public mirror declares nginx as a submodule but omits the gitlink. Pin the
# tokenizer source explicitly. Two small compatibility changes make the
# standalone parser build on Linux against the pinned nginx release: Linux has
# no dirent.d_namlen, and nginx now defines its allocator globals itself. The
# same patch teaches the resumable collector to retry transient HTTP 408/425
# and gateway failures instead of discarding an otherwise healthy long run.
if [ ! -d "$ngxray_dir/nginx/.git" ]; then
    git clone https://github.com/nginx/nginx.git "$ngxray_dir/nginx"
fi
git -C "$ngxray_dir/nginx" fetch --depth 1 origin "$nginx_commit"
git -C "$ngxray_dir/nginx" checkout --detach "$nginx_commit"
if git -C "$ngxray_dir" apply --unidiff-zero --check "$script_dir/ngxray-compat.patch"; then
    git -C "$ngxray_dir" apply --unidiff-zero "$script_dir/ngxray-compat.patch"
elif git -C "$ngxray_dir" apply --unidiff-zero --reverse --check "$script_dir/ngxray-compat.patch"; then
    : # already applied by an earlier resumable run
else
    echo "ngxray compatibility patch does not apply to the pinned commit" >&2
    exit 1
fi

if [ ! -x "$venv_dir/bin/python" ]; then
    python3 -m venv "$venv_dir"
fi
"$venv_dir/bin/python" -m pip install --disable-pip-version-check requests==2.34.2

"$venv_dir/bin/python" "$ngxray_dir/corpus_tools/collect_github_nginx_corpus.py" \
    --output-dir "$corpus_dir" \
    --target "$collector_target" \
    --per-page 100 \
    --page-limit 10 \
    --workers 8 \
    --sleep 2.1 \
    --max-rate-wait 90

# Extraction output is derived and the upstream extractor chooses a new name
# when an old output exists. Clear only this known generated directory so a
# resumed collection produces a deterministic one-to-one metadata join.
mkdir -p "$corpus_dir/extracted"
find "$corpus_dir/extracted" -mindepth 1 -maxdepth 1 -type f -delete
"$venv_dir/bin/python" "$ngxray_dir/corpus_tools/extract_nginx_configs.py" \
    --input-dir "$corpus_dir/raw" \
    --output-dir "$corpus_dir/extracted"

make -C "$ngxray_dir" -j2
find "$corpus_dir/extracted" -type f -name '*.conf' -print \
    | LC_ALL=C sort \
    | "$ngxray_dir/build/nginx_conf_parse" - \
        > "$corpus_dir/parsed.json" \
        2> "$corpus_dir/parser-errors.log"

COLLECTOR_COMMIT=$ngxray_commit \
NGINX_COMMIT=$nginx_commit \
COLLECTOR_TARGET=$collector_target \
COLLECTOR_PATH="$ngxray_dir/corpus_tools/collect_github_nginx_corpus.py" \
PATCH_PATH="$script_dir/ngxray-compat.patch" \
RAW_METADATA="$corpus_dir/raw/metadata.json" \
EXTRACTED_METADATA="$corpus_dir/extracted/metadata.json" \
MANIFEST_PATH="$corpus_dir/manifest.json" \
"$venv_dir/bin/python" - <<'PY'
import datetime
import hashlib
import json
import os
from pathlib import Path

import requests

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

raw = json.loads(Path(os.environ["RAW_METADATA"]).read_text())
extracted = json.loads(Path(os.environ["EXTRACTED_METADATA"]).read_text())
manifest = {
    "collected_at": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
    "collector_repository": "https://github.com/califio/ngxray",
    "collector_commit": os.environ["COLLECTOR_COMMIT"],
    "collector_script_sha256": digest(os.environ["COLLECTOR_PATH"]),
    "collector_target": int(os.environ["COLLECTOR_TARGET"]),
    "collector_query_count": 102,
    "collector_arguments": {
        "per_page": 100,
        "page_limit": 10,
        "workers": 8,
        "sleep_seconds": 2.1,
        "max_rate_wait_seconds": 90,
    },
    "requests_version": requests.__version__,
    "nginx_repository": "https://github.com/nginx/nginx",
    "nginx_commit": os.environ["NGINX_COMMIT"],
    "nginx_release": "1.31.1",
    "parser_compatibility_patch_sha256": digest(os.environ["PATCH_PATH"]),
    "raw_unique_files": len(raw),
    "extracted_unique_configs": len(extracted),
    "sampling": "GitHub Code Search query union; globally content-deduplicated",
}
Path(os.environ["MANIFEST_PATH"]).write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n"
)
PY

"$venv_dir/bin/python" "$script_dir/nginx_corpus_census.py" \
    --parser-json "$corpus_dir/parsed.json" \
    --metadata "$corpus_dir/extracted/metadata.json" \
    --manifest "$corpus_dir/manifest.json" \
    --nginx-source "$ngxray_dir/nginx/src" \
    --output-dir "$output_dir"
