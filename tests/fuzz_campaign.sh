#!/bin/sh
# Scheduled coverage-guided campaign.  The smoke gate remains quick; this
# script gives every target sustained CPU time and retains minimized corpora.
set -eu

cd "$(dirname "$0")/.."
NIGHTLY=${VAPACHE_NIGHTLY_TOOLCHAIN:-nightly}

if ! cargo +"$NIGHTLY" fuzz --version >/dev/null 2>&1; then
    echo "fuzz-campaign: cargo-fuzz is required" >&2
    exit 2
fi
cargo +"$NIGHTLY" --version >/dev/null

SECONDS_PER_TARGET=${FUZZ_SECONDS_PER_TARGET:-300}
MAX_LEN=${FUZZ_MAX_LEN:-1048576}
TARGETS=${FUZZ_TARGETS:-"http_request http_connection http_fields config_sections config_compile config_grammars htaccess_walk rewrite_expr cgi_response fastcgi_records proxy_response websocket_negotiation h2_frames h2_output h2_stateful cache_metadata tls_policy ocsp_der pcre2_differential pcre2_grammar pcre2_resource resource_transitions policy_path whole_request_differential"}

for target in $TARGETS; do
    echo "fuzz-campaign: $target (${SECONDS_PER_TARGET}s)"
    corpus="fuzz/corpus/$target"
    mkdir -p "$corpus" "fuzz/artifacts/$target"
    dictionary_target=$target
    [ "$target" != pcre2_grammar ] || dictionary_target=pcre2_differential
    dictionary=
    [ ! -f "fuzz/dictionaries/$dictionary_target.dict" ] \
        || dictionary="-dict=fuzz/dictionaries/$dictionary_target.dict"
    target_max_len=$MAX_LEN
    [ "$target" != whole_request_differential ] || target_max_len=256
    cargo +"$NIGHTLY" fuzz run "$target" "$corpus" -- \
        -max_total_time="$SECONDS_PER_TARGET" \
        -timeout=10 \
        -rss_limit_mb=4096 \
        -max_len="$target_max_len" \
        -artifact_prefix="fuzz/artifacts/$target/" \
        $dictionary
    if [ "${FUZZ_MINIMIZE_CORPUS:-0}" = 1 ]; then
        echo "fuzz-campaign: minimizing cumulative corpus for $target"
        cargo +"$NIGHTLY" fuzz cmin "$target" "$corpus" -- \
            -timeout=10 \
            -rss_limit_mb=4096 \
            -max_len="$target_max_len" \
            $dictionary
    fi
done
