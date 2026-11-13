#!/usr/bin/env bash
# Resumable local fuzz campaign for security-sensitive composed behavior.
# Corpora and logs live in resumable local state. Findings are retained under
# adversarial/long_fuzz_findings so a completed campaign leaves every crash,
# timeout and OOM visible for triage.
set -Eeuo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

NIGHTLY=${HTTPD_RS_NIGHTLY_TOOLCHAIN:-nightly-2026-10-29}
TOTAL_SECONDS=${LONG_FUZZ_SECONDS:-28800}
QUANTUM_SECONDS=${LONG_FUZZ_QUANTUM:-600}
PARALLEL_JOBS=${LONG_FUZZ_JOBS:-2}
STATE_DIR=${LONG_FUZZ_STATE_DIR:-$REPO_ROOT/.fuzz-long}
FINDINGS_DIR=$REPO_ROOT/adversarial/long_fuzz_findings
PROFILE=${LONG_FUZZ_PROFILE:-full}
TARGET_OVERRIDE=${LONG_FUZZ_TARGETS:-}
RSS_LIMIT_MB=${LONG_FUZZ_RSS_LIMIT_MB:-4096}
MINIMIZE=${LONG_FUZZ_MINIMIZE:-0}
GENERATE_COVERAGE=${LONG_FUZZ_COVERAGE:-0}
STRICT_SEMANTIC=${LONG_FUZZ_STRICT_SEMANTIC:-0}
NIGHTLY_IMPORT=${LONG_FUZZ_NIGHTLY_RUN:-}
IMPORT_DIRS=()
[[ -z ${LONG_FUZZ_IMPORT_DIR:-} ]] || IMPORT_DIRS+=("$LONG_FUZZ_IMPORT_DIR")
DRY_RUN=0

ALL_TARGETS="http_request http_connection http_fields request_identity config_physical_lines config_sections config_compile config_grammars htaccess_walk rewrite_expr cgi_response fastcgi_records proxy_response websocket_negotiation h2_frames h2_output h2_stateful cache_metadata cache_stateful tls_policy tls_identity_reload ocsp_der pcre2_differential pcre2_grammar pcre2_resource resource_transitions policy_path whole_request_differential multi_request_state"
HIGH_YIELD_TARGETS="request_identity config_physical_lines config_sections config_compile config_grammars htaccess_walk rewrite_expr h2_frames h2_output h2_stateful cache_stateful tls_identity_reload pcre2_differential pcre2_grammar pcre2_resource resource_transitions policy_path whole_request_differential multi_request_state"

usage() {
    cat <<'EOF'
Usage: tests/long_fuzz.sh [options]

  --hours N          total wall-clock duration (default: 8)
  --seconds N        total wall-clock duration in seconds
  --quantum N        seconds per target before rotating (default: 600)
  --jobs N           targets to run concurrently (default: 2)
  --profile NAME     continuation, adversarial, or full/all (default: full)
  --targets "A B"    explicit space-separated target list
  --state DIR        persistent corpus/log directory
  --import DIR       merge a downloaded fuzz artifact tree; may be repeated
  --nightly RUN      import fuzz artifacts from a GitHub run ID, or "latest"
  --minimize         minimize each accumulated corpus after a clean run
  --coverage         generate per-target LLVM line/branch reports afterward
  --strict-semantic  fail if a required semantic census bucket is absent
  --dry-run          validate and print the schedule without fuzzing
  -h, --help         show this help

Environment equivalents: LONG_FUZZ_SECONDS, LONG_FUZZ_QUANTUM,
LONG_FUZZ_JOBS, LONG_FUZZ_PROFILE, LONG_FUZZ_TARGETS,
LONG_FUZZ_STATE_DIR, LONG_FUZZ_RSS_LIMIT_MB, LONG_FUZZ_MINIMIZE, and
LONG_FUZZ_IMPORT_DIR, LONG_FUZZ_NIGHTLY_RUN, LONG_FUZZ_COVERAGE,
LONG_FUZZ_STRICT_SEMANTIC, and HTTPD_RS_NIGHTLY_TOOLCHAIN.

Fuzz findings are always retained by target under
adversarial/long_fuzz_findings. A finding does not stop the campaign.

Examples:
  tests/long_fuzz.sh --hours 12 --jobs 4
  tests/long_fuzz.sh --nightly latest --hours 12 --jobs 4
  tests/long_fuzz.sh --profile continuation --hours 2
  tests/long_fuzz.sh --targets "whole_request_differential multi_request_state" --hours 6
EOF
}

need_value() {
    if (($# < 2)); then
        echo "long-fuzz: $1 requires a value" >&2
        exit 2
    fi
}

while (($#)); do
    case "$1" in
        --hours)
            need_value "$@"
            if [[ ! $2 =~ ^[1-9][0-9]*$ ]]; then
                echo "long-fuzz: hours must be a positive integer (got $2)" >&2
                exit 2
            fi
            TOTAL_SECONDS=$(( $2 * 3600 ))
            shift 2
            ;;
        --seconds)
            need_value "$@"
            TOTAL_SECONDS=$2
            shift 2
            ;;
        --quantum)
            need_value "$@"
            QUANTUM_SECONDS=$2
            shift 2
            ;;
        --jobs)
            need_value "$@"
            PARALLEL_JOBS=$2
            shift 2
            ;;
        --profile)
            need_value "$@"
            PROFILE=$2
            shift 2
            ;;
        --targets)
            need_value "$@"
            TARGET_OVERRIDE=$2
            shift 2
            ;;
        --state)
            need_value "$@"
            STATE_DIR=$2
            shift 2
            ;;
        --import)
            need_value "$@"
            IMPORT_DIRS+=("$2")
            shift 2
            ;;
        --nightly)
            need_value "$@"
            NIGHTLY_IMPORT=$2
            shift 2
            ;;
        --minimize)
            MINIMIZE=1
            shift
            ;;
        --coverage)
            GENERATE_COVERAGE=1
            shift
            ;;
        --strict-semantic)
            STRICT_SEMANTIC=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "long-fuzz: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

require_positive_integer() {
    local name=$1 value=$2
    if [[ ! $value =~ ^[1-9][0-9]*$ ]]; then
        echo "long-fuzz: $name must be a positive integer (got $value)" >&2
        exit 2
    fi
}

require_positive_integer duration "$TOTAL_SECONDS"
require_positive_integer quantum "$QUANTUM_SECONDS"
require_positive_integer jobs "$PARALLEL_JOBS"
require_positive_integer rss-limit "$RSS_LIMIT_MB"
if [[ $MINIMIZE != 0 && $MINIMIZE != 1 ]]; then
    echo "long-fuzz: LONG_FUZZ_MINIMIZE must be 0 or 1 (got $MINIMIZE)" >&2
    exit 2
fi
if [[ $GENERATE_COVERAGE != 0 && $GENERATE_COVERAGE != 1 ]]; then
    echo "long-fuzz: LONG_FUZZ_COVERAGE must be 0 or 1 (got $GENERATE_COVERAGE)" >&2
    exit 2
fi
if [[ $STRICT_SEMANTIC != 0 && $STRICT_SEMANTIC != 1 ]]; then
    echo "long-fuzz: LONG_FUZZ_STRICT_SEMANTIC must be 0 or 1 (got $STRICT_SEMANTIC)" >&2
    exit 2
fi

if [[ -n $TARGET_OVERRIDE ]]; then
    TARGET_TEXT=$TARGET_OVERRIDE
else
    case "$PROFILE" in
        continuation)
            TARGET_TEXT="config_physical_lines config_sections config_compile config_grammars htaccess_walk"
            ;;
        adversarial)
            TARGET_TEXT="request_identity config_physical_lines config_sections config_compile config_grammars htaccess_walk rewrite_expr pcre2_differential pcre2_grammar pcre2_resource policy_path whole_request_differential multi_request_state h2_frames h2_output h2_stateful cache_stateful tls_identity_reload resource_transitions"
            ;;
        full|all)
            TARGET_TEXT=$ALL_TARGETS
            ;;
        *)
            echo "long-fuzz: unknown profile: $PROFILE" >&2
            exit 2
            ;;
    esac
fi
read -r -a TARGETS <<<"$TARGET_TEXT"
if ((${#TARGETS[@]} == 0)); then
    echo "long-fuzz: no targets selected" >&2
    exit 2
fi
if ((PARALLEL_JOBS > ${#TARGETS[@]})); then
    PARALLEL_JOBS=${#TARGETS[@]}
fi

declare -A SEEN=()
for target in "${TARGETS[@]}"; do
    if [[ " $ALL_TARGETS " != *" $target "* ]]; then
        echo "long-fuzz: unknown target: $target" >&2
        exit 2
    fi
    if [[ -n ${SEEN[$target]:-} ]]; then
        echo "long-fuzz: duplicate target: $target" >&2
        exit 2
    fi
    SEEN[$target]=1
done

# The full campaign touches every target before repeating any one of them,
# then gives a second slot to the composed/stateful surfaces with the highest
# historical adversarial yield. Explicit target lists remain unweighted so a
# focused investigation has unsurprising allocation.
SCHEDULE_TARGETS=("${TARGETS[@]}")
if [[ -z $TARGET_OVERRIDE && ( $PROFILE == full || $PROFILE == all ) ]]; then
    for target in $HIGH_YIELD_TARGETS; do
        if [[ -n ${SEEN[$target]:-} ]]; then
            SCHEDULE_TARGETS+=("$target")
        fi
    done
fi

target_max_len() {
    case "$1" in
        config_physical_lines) echo 65536 ;;
        request_identity|tls_identity_reload) echo 256 ;;
        cache_stateful) echo 128 ;;
        whole_request_differential) echo 256 ;;
        multi_request_state) echo 96 ;;
        *) echo 1048576 ;;
    esac
}

target_dictionary() {
    local target=$1 dictionary_target=$1
    [[ $target != pcre2_grammar ]] || dictionary_target=pcre2_differential
    local dictionary="fuzz/dictionaries/$dictionary_target.dict"
    if [[ -f $dictionary ]]; then
        printf '%s\n' "$dictionary"
    fi
    return 0
}

run_printed() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    if ((DRY_RUN == 0)); then
        "$@"
    fi
}

import_seeds() {
    local target=$1 destination=$STATE_DIR/corpus/$target seed digest
    mkdir -p "$destination" "$FINDINGS_DIR/$target" "$STATE_DIR/logs/$target"
    shopt -s nullglob
    for seed in "fuzz/corpus/$target"/*; do
        [[ -f $seed ]] || continue
        digest=$(sha256sum "$seed" | awk '{print $1}')
        [[ -e $destination/$digest ]] || cp "$seed" "$destination/$digest"
    done
    shopt -u nullglob
}

copy_content_addressed() {
    local source=$1 destination=$2 digest
    [[ -f $source && ! -L $source ]] || return 0
    digest=$(sha256sum "$source" | awk '{print $1}')
    [[ -e $destination/$digest ]] || cp "$source" "$destination/$digest"
}

import_tree() {
    local root=$1 target source imported=0
    if [[ ! -d $root ]]; then
        echo "long-fuzz: import directory does not exist: $root" >&2
        return 1
    fi
    root=$(cd "$root" && pwd)
    echo "long-fuzz: importing retained corpora/artifacts from $root"
    for target in "${TARGETS[@]}"; do
        while IFS= read -r -d '' source; do
            copy_content_addressed "$source" "$STATE_DIR/corpus/$target"
            imported=$((imported + 1))
        done < <(find "$root" -type f ! -type l \
            \( -path "*/fuzz/corpus/$target/*" -o -path "*/corpus/$target/*" \) \
            -print0 2>/dev/null)
        while IFS= read -r -d '' source; do
            copy_content_addressed "$source" "$FINDINGS_DIR/$target"
            imported=$((imported + 1))
        done < <(find "$root" -type f ! -type l \
            \( -path "*/fuzz/artifacts/$target/*" \
                -o -path "*/artifacts/$target/*" \
                -o -path "*/long_fuzz_findings/$target/*" \) \
            -print0 2>/dev/null)
    done
    echo "long-fuzz: considered $imported imported corpus/artifact files"
}

download_nightly() {
    local requested=$1 run_id destination
    [[ -n $requested ]] || return 0
    if ((DRY_RUN)); then
        echo "long-fuzz: would import GitHub nightly run $requested"
        return 0
    fi
    command -v gh >/dev/null 2>&1 || {
        echo "long-fuzz: gh is required for --nightly" >&2
        return 2
    }
    if [[ $requested == latest ]]; then
        run_id=$(gh run list --workflow nightly.yml --status completed --limit 1 \
            --json databaseId --jq '.[0].databaseId')
    elif [[ $requested =~ ^[1-9][0-9]*$ ]]; then
        run_id=$requested
    else
        echo "long-fuzz: --nightly must be a run ID or latest (got $requested)" >&2
        return 2
    fi
    [[ -n $run_id ]] || {
        echo "long-fuzz: no completed nightly run was found" >&2
        return 1
    }
    destination=$STATE_DIR/imports/nightly-$run_id
    if [[ ! -f $destination/.complete ]]; then
        mkdir -p "$destination"
        echo "long-fuzz: downloading fuzz-* artifacts from GitHub run $run_id"
        if ! gh run download "$run_id" --pattern 'fuzz-*' --dir "$destination"; then
            echo "long-fuzz: GitHub artifact download failed; use --import with a manually downloaded artifact tree" >&2
            return 1
        fi
        touch "$destination/.complete"
    fi
    IMPORT_DIRS+=("$destination")
}

run_report() {
    local output=$1 strict=${2:-0}
    local -a command=(python3 tests/fuzz_report.py
        --state "$STATE_DIR"
        --targets "${TARGETS[*]}"
        --output "$output")
    ((strict == 0)) || command+=(--strict-semantic)
    "${command[@]}"
}

seed_semantic_matrix() {
    python3 tests/fuzz_report.py \
        --state "$STATE_DIR" \
        --targets "${TARGETS[*]}" \
        --output "$STATE_DIR/seed-matrix.json" \
        --seed-matrix
}

run_coverage_reports() {
    local sysroot host llvm_bin target corpus max_len binary report_dir
    ((GENERATE_COVERAGE)) || return 0
    sysroot=$(rustc +"$NIGHTLY" --print sysroot)
    host=$(rustc +"$NIGHTLY" -vV | awk '/^host:/ {print $2}')
    llvm_bin=$sysroot/lib/rustlib/$host/bin
    if [[ ! -x $llvm_bin/llvm-profdata || ! -x $llvm_bin/llvm-cov ]]; then
        echo "long-fuzz: --coverage requires llvm-tools-preview for $NIGHTLY" >&2
        echo "  rustup component add --toolchain $NIGHTLY llvm-tools-preview" >&2
        return 2
    fi
    report_dir=$STATE_DIR/coverage
    mkdir -p "$report_dir"
    for target in "${TARGETS[@]}"; do
        corpus=$STATE_DIR/corpus/$target
        max_len=$(target_max_len "$target")
        echo "long-fuzz: source coverage target=$target"
        RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Zcoverage-options=branch" \
        cargo +"$NIGHTLY" fuzz coverage \
            --target-dir "$STATE_DIR/coverage-target" \
            "$target" "$corpus" -- -timeout=10 -max_len="$max_len"
        binary=$STATE_DIR/coverage-target/$host/release/$target
        if [[ ! -x $binary ]]; then
            echo "long-fuzz: coverage binary not found: $binary" >&2
            return 1
        fi
        cp "fuzz/coverage/$target/coverage.profdata" "$report_dir/$target.profdata"
        "$llvm_bin/llvm-cov" report "$binary" \
            -instr-profile="$report_dir/$target.profdata" \
            '--ignore-filename-regex=(\.cargo|rustc|/root/\.rustup)' \
            >"$report_dir/$target.txt"
        "$llvm_bin/llvm-cov" export "$binary" \
            -instr-profile="$report_dir/$target.profdata" \
            '--ignore-filename-regex=(\.cargo|rustc|/root/\.rustup)' \
            >"$report_dir/$target.json"
    done
    echo "long-fuzz: LLVM coverage reports retained at $report_dir"
}

archive_artifact() {
    local source=$1 target=$2 destination digest
    [[ -f $source && ! -L $source ]] || return 0
    mkdir -p "$FINDINGS_DIR/$target"
    destination=$FINDINGS_DIR/$target/$(basename "$source")
    if [[ -e $destination ]]; then
        if cmp -s "$source" "$destination"; then
            rm "$source"
            return 0
        fi
        digest=$(sha256sum "$source" | awk '{print $1}')
        destination=$FINDINGS_DIR/$target/$(basename "$source")-$digest
    fi
    mv "$source" "$destination"
    echo "long-fuzz: migrated retained finding to $destination"
}

migrate_artifact_tree() {
    local root=$1 artifact target
    [[ -d $root ]] || return 0
    while IFS= read -r -d '' artifact; do
        target=$(basename "$(dirname "$artifact")")
        archive_artifact "$artifact" "$target"
    done < <(find "$root" -mindepth 2 -maxdepth 2 -type f ! -type l -print0)
    find "$root" -depth -type d -empty -delete 2>/dev/null || true
}

declare -A REPORTED_ARTIFACTS=()
report_artifacts() {
    local artifact target digest size
    while IFS= read -r -d '' artifact; do
        [[ -z ${REPORTED_ARTIFACTS[$artifact]:-} ]] || continue
        REPORTED_ARTIFACTS[$artifact]=1
        target=$(basename "$(dirname "$artifact")")
        digest=$(sha256sum "$artifact" | awk '{print $1}')
        size=$(wc -c <"$artifact" | tr -d ' ')
        printf 'long-fuzz: artifact target=%s size=%s sha256=%s path=%s\n' \
            "$target" "$size" "$digest" "$artifact" >&2
        printf '  replay: cargo +%q fuzz run %q %q -- -runs=1\n' \
            "$NIGHTLY" "$target" "$artifact" >&2
    done < <(find "$FINDINGS_DIR" -mindepth 2 -type f -print0 2>/dev/null)
    return 0
}

replay_artifacts() {
    local target artifact log max_len dictionary
    local -a command
    for target in "${TARGETS[@]}"; do
        max_len=$(target_max_len "$target")
        dictionary=$(target_dictionary "$target")
        shopt -s nullglob
        for artifact in "$FINDINGS_DIR/$target"/*; do
            [[ -f $artifact ]] || continue
            log=$STATE_DIR/logs/$target/replay-$(basename "$artifact").log
            command=(cargo +"$NIGHTLY" fuzz run "$target" "$artifact" --
                -runs=1
                -timeout=10
                -rss_limit_mb="$RSS_LIMIT_MB"
                -max_len="$max_len")
            [[ -z $dictionary ]] || command+=("-dict=$dictionary")
            echo "long-fuzz: replaying $artifact"
            if ! "${command[@]}" >"$log" 2>&1; then
                echo "long-fuzz: retained finding still fails (campaign will continue): $artifact" >&2
            else
                echo "long-fuzz: retained finding no longer fails: $artifact"
            fi
        done
        shopt -u nullglob
    done
}

CHILDREN=()
interrupt_campaign() {
    trap - INT TERM
    echo "long-fuzz: interrupt received; stopping active fuzzers" >&2
    local pid
    for pid in "${CHILDREN[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${CHILDREN[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done
    report_artifacts || true
    run_report "$STATE_DIR/summary-interrupted.json" 0 || true
    echo "long-fuzz: state retained at $STATE_DIR" >&2
    exit 130
}
trap interrupt_campaign INT TERM

mkdir -p "$STATE_DIR/corpus" "$STATE_DIR/logs" "$FINDINGS_DIR"
STATE_DIR=$(cd "$STATE_DIR" && pwd)

echo "long-fuzz: profile=$PROFILE duration=${TOTAL_SECONDS}s quantum=${QUANTUM_SECONDS}s jobs=$PARALLEL_JOBS"
echo "long-fuzz: state=$STATE_DIR"
echo "long-fuzz: findings=$FINDINGS_DIR"
echo "long-fuzz: targets=${TARGETS[*]}"
echo "long-fuzz: weighted-slots=${#SCHEDULE_TARGETS[@]} schedule=${SCHEDULE_TARGETS[*]}"

python3 tests/fuzz_report.py --check-specs

if ((DRY_RUN == 0)); then
    if ! cargo +"$NIGHTLY" fuzz --version >/dev/null 2>&1; then
        echo "long-fuzz: cargo-fuzz is required for toolchain $NIGHTLY" >&2
        exit 2
    fi
    cargo +"$NIGHTLY" --version >/dev/null
fi

for target in "${TARGETS[@]}"; do
    import_seeds "$target"
done
if ((DRY_RUN == 0)); then
    migrate_artifact_tree "$STATE_DIR/artifacts"
    migrate_artifact_tree "$REPO_ROOT/fuzz/artifacts"
fi
seed_semantic_matrix

download_nightly "$NIGHTLY_IMPORT"
for import_dir in "${IMPORT_DIRS[@]}"; do
    import_tree "$import_dir"
done
run_report "$STATE_DIR/baseline.json" 0

# The physical continuation state space is finite enough to enumerate. Run
# that exact matrix before spending CPU on mutation so fuzzing is reserved for
# unbounded composition rather than rediscovering known boundary products.
run_printed env RUSTFLAGS=-Awarnings cargo test -p httpd-rs --lib \
    config_frontend::tests::continuation_matrix_exhausts_boundaries_chains_and_near_misses \
    -- --exact

# Build sequentially once. Parallel cargo-fuzz invocations would otherwise
# serialize on Cargo's package-cache locks and waste the first rotation.
for target in "${TARGETS[@]}"; do
    run_printed cargo +"$NIGHTLY" fuzz build "$target"
done

if ((DRY_RUN)); then
    echo "long-fuzz: dry-run complete"
    exit 0
fi

replay_artifacts

started=$(date +%s)
deadline=$((started + TOTAL_SECONDS))
cursor=0
cycle=1

while (( $(date +%s) < deadline )); do
    CHILDREN=()
    BATCH_TARGETS=()
    for ((slot = 0; slot < PARALLEL_JOBS; slot++)); do
        now=$(date +%s)
        remaining=$((deadline - now))
        ((remaining > 0)) || break
        slice=$QUANTUM_SECONDS
        ((slice <= remaining)) || slice=$remaining

        target=${SCHEDULE_TARGETS[$cursor]}
        cursor=$(((cursor + 1) % ${#SCHEDULE_TARGETS[@]}))
        corpus=$STATE_DIR/corpus/$target
        artifacts=$FINDINGS_DIR/$target/
        log=$STATE_DIR/logs/$target/cycle-$cycle.log
        max_len=$(target_max_len "$target")
        dictionary=$(target_dictionary "$target")

        echo "long-fuzz: cycle=$cycle target=$target slice=${slice}s log=$log"
        command=(cargo +"$NIGHTLY" fuzz run "$target" "$corpus" --
            -max_total_time="$slice"
            -fork=1
            -ignore_crashes=1
            -ignore_timeouts=1
            -ignore_ooms=1
            -timeout=10
            -rss_limit_mb="$RSS_LIMIT_MB"
            -max_len="$max_len"
            -print_final_stats=1
            -artifact_prefix="$artifacts")
        [[ -z $dictionary ]] || command+=("-dict=$dictionary")
        "${command[@]}" >"$log" 2>&1 &
        CHILDREN+=("$!")
        BATCH_TARGETS+=("$target")
        cycle=$((cycle + 1))
    done

    failed=0
    failed_target=
    for index in "${!CHILDREN[@]}"; do
        if ! wait "${CHILDREN[$index]}"; then
            failed=1
            failed_target=${BATCH_TARGETS[$index]}
        fi
    done
    CHILDREN=()
    if ((failed)); then
        # Fork mode turns target crashes, timeouts and OOMs into retained
        # findings and continues. A non-zero command here is therefore an
        # infrastructure failure rather than an ordinary fuzz finding.
        echo "long-fuzz: fuzzer infrastructure failed: $failed_target" >&2
        report_artifacts || true
        run_report "$STATE_DIR/summary-failed.json" 0 || true
        echo "long-fuzz: logs and resumable state: $STATE_DIR" >&2
        exit 1
    fi
    report_artifacts || true
done

if ((MINIMIZE)); then
    for target in "${TARGETS[@]}"; do
        corpus=$STATE_DIR/corpus/$target
        max_len=$(target_max_len "$target")
        dictionary=$(target_dictionary "$target")
        command=(cargo +"$NIGHTLY" fuzz cmin "$target" "$corpus" --
            -timeout=10
            -rss_limit_mb="$RSS_LIMIT_MB"
            -max_len="$max_len")
        [[ -z $dictionary ]] || command+=("-dict=$dictionary")
        run_printed "${command[@]}"
    done
fi

# cmin preserves structural features, not application-level case labels.
# Restore the finite semantic matrix so the resumable corpus retains both.
seed_semantic_matrix

run_coverage_reports

elapsed=$(( $(date +%s) - started ))
echo "long-fuzz: completed campaign after ${elapsed}s"
echo "long-fuzz: corpora and logs retained at $STATE_DIR"
echo "long-fuzz: findings retained at $FINDINGS_DIR"
report_artifacts || true
run_report "$STATE_DIR/summary.json" "$STRICT_SEMANTIC"
