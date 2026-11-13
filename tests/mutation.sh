#!/bin/sh
# Measure whether tests detect deliberately corrupted security decisions.
set -eu

cd "$(dirname "$0")/.."
command -v cargo-mutants >/dev/null 2>&1 || {
    echo "mutation: cargo-mutants is required" >&2
    exit 2
}

files=${MUTATION_FILES:-"access.rs request_plan.rs scope_policy.rs cache.rs http.rs rewrite.rs resource.rs config_frontend.rs"}
args=
for file in $files; do
    args="$args --file crates/server/src/$file"
done

# In-place mode avoids cloning a multi-gigabyte Rust target directory for
# every worker. cargo-mutants restores each source file before it advances.
# The test binaries are serialized because several hardening tests deliberately
# exercise process-global caches and failpoint registries.
if [ "${MUTATION_IN_PLACE:-1}" = 1 ]; then
    # shellcheck disable=SC2086 -- the repeated --file options are intentional.
    cargo mutants --package vapached --in-place \
        --timeout "${MUTATION_TIMEOUT:-300}" $args "$@" \
        -- -- --test-threads=1
else
    # shellcheck disable=SC2086 -- the repeated --file options are intentional.
    cargo mutants --package vapached --jobs "${MUTATION_JOBS:-2}" \
        --timeout "${MUTATION_TIMEOUT:-300}" $args "$@" \
        -- -- --test-threads=1
fi
