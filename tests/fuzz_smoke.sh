#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
NIGHTLY=${HTTPD_RS_NIGHTLY_TOOLCHAIN:-nightly-2026-10-29}

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
config_physical_runs=${FUZZ_CONFIG_PHYSICAL_RUNS:-16384}
resource_runs=${FUZZ_RESOURCE_RUNS:-1024}
brotli_runs=${FUZZ_BROTLI_RUNS:-512}
whole_request_runs=${FUZZ_WHOLE_REQUEST_RUNS:-1024}
multi_request_runs=${FUZZ_MULTI_REQUEST_RUNS:-1024}
corpus_root=$(mktemp -d /tmp/httpd-rs-fuzz-smoke.XXXXXX)
trap 'rm -rf "$corpus_root"' EXIT INT TERM
targets=${FUZZ_TARGETS:-"http_request http_connection http_fields request_identity config_physical_lines config_sections config_compile config_grammars htaccess_walk rewrite_expr cgi_response fastcgi_records proxy_response websocket_negotiation h2_frames h2_output h2_stateful cache_metadata cache_stateful tls_policy tls_identity_reload ocsp_der pcre2_differential pcre2_grammar pcre2_resource resource_transitions brotli_resource policy_path whole_request_differential multi_request_state"}

for target in $targets; do
    mkdir "$corpus_root/$target"
    cp "fuzz/corpus/$target"/* "$corpus_root/$target/"
    dictionary_target=$target
    [ "$target" != pcre2_grammar ] || dictionary_target=pcre2_differential
    dictionary=
    [ ! -f "fuzz/dictionaries/$dictionary_target.dict" ] \
        || dictionary="-dict=fuzz/dictionaries/$dictionary_target.dict"
    target_runs=$runs
    target_max_len=262144
    [ "$target" != rewrite_expr ] || target_runs=$rewrite_expr_runs
    case "$target" in
        config_physical_lines)
            target_runs=$config_physical_runs
            target_max_len=65536
            ;;
        request_identity|tls_identity_reload) target_max_len=256 ;;
        cache_stateful) target_max_len=128 ;;
        pcre2_*) target_runs=$pcre2_runs ;;
        resource_transitions) target_runs=$resource_runs ;;
        brotli_resource)
            target_runs=$brotli_runs
            target_max_len=262144
            ;;
        whole_request_differential)
            target_runs=$whole_request_runs
            target_max_len=256
            ;;
        multi_request_state)
            target_runs=$multi_request_runs
            target_max_len=96
            ;;
    esac
    cargo +"$NIGHTLY" fuzz run "$target" "$corpus_root/$target" -- \
        -runs="$target_runs" -timeout=5 -max_len="$target_max_len" $dictionary
done
