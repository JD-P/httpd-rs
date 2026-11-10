#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
NIGHTLY=${VAPACHE_NIGHTLY_TOOLCHAIN:-nightly}

if ! cargo +"$NIGHTLY" fuzz --version >/dev/null 2>&1; then
    echo "fuzz-smoke: cargo-fuzz is required" >&2
    exit 2
fi
cargo +"$NIGHTLY" --version >/dev/null
cargo check --manifest-path fuzz/Cargo.toml

runs=${FUZZ_SMOKE_RUNS:-64}
# The P24-A UTF-8 boundary crash took a sustained campaign to discover. Keep
# its artifact in the corpus and give the expression parser enough mutations
# to exercise adjacent delimiter/string shapes in the ordinary smoke gate.
rewrite_expr_runs=${FUZZ_REWRITE_EXPR_RUNS:-16384}
pcre2_runs=${FUZZ_PCRE2_RUNS:-16384}
resource_runs=${FUZZ_RESOURCE_RUNS:-1024}
corpus_root=$(mktemp -d /tmp/vapache-fuzz-smoke.XXXXXX)
trap 'rm -rf "$corpus_root"' EXIT INT TERM
targets=${FUZZ_TARGETS:-"http_request http_connection config_sections config_compile htaccess_walk rewrite_expr cgi_response fastcgi_records proxy_response websocket_negotiation h2_frames h2_output cache_metadata tls_policy ocsp_der pcre2_differential pcre2_resource resource_transitions"}

for target in $targets; do
    mkdir "$corpus_root/$target"
    cp "fuzz/corpus/$target"/* "$corpus_root/$target/"
    dictionary=
    [ ! -f "fuzz/dictionaries/$target.dict" ] \
        || dictionary="-dict=fuzz/dictionaries/$target.dict"
    target_runs=$runs
    [ "$target" != rewrite_expr ] || target_runs=$rewrite_expr_runs
    case "$target" in
        pcre2_*) target_runs=$pcre2_runs ;;
        resource_transitions) target_runs=$resource_runs ;;
    esac
    cargo +"$NIGHTLY" fuzz run "$target" "$corpus_root/$target" -- \
        -runs="$target_runs" -timeout=5 -max_len=262144 $dictionary
done
