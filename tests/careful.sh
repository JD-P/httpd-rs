#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
NIGHTLY=${HTTPD_RS_NIGHTLY_TOOLCHAIN:-nightly}
if ! command -v cargo-careful >/dev/null 2>&1; then
    echo "careful: cargo-careful is required" >&2
    exit 2
fi
cargo +"$NIGHTLY" careful test --workspace --all-targets -- --test-threads=1
