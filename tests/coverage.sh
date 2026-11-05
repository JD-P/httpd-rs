#!/bin/sh
# Combined line coverage for vapached: Rust unit tests plus the end-to-end
# conformance suite.
#
# The server and test binaries are built with -C instrument-coverage into
# target/cov, the Python suite drives the real binary (Apache is only used for
# differential checks), and llvm-profdata/llvm-cov merge all profiles.
set -eu

cd "$(dirname "$0")/.."

SYSROOT="$(rustc --print sysroot)"
HOST="$(rustc -vV | awk '/^host:/ {print $2}')"
LLVM_BIN="$SYSROOT/lib/rustlib/$HOST/bin"
PROFILE_DIR="${PROFILE_DIR:-/tmp/vapcov}"
export COVERAGE_TARGET_DIR="${COVERAGE_TARGET_DIR:-target/cov}"

if [ ! -x "$LLVM_BIN/llvm-profdata" ] || [ ! -x "$LLVM_BIN/llvm-cov" ]; then
    echo "coverage: missing llvm-tools-preview for $(rustc --version)" >&2
    echo "coverage: install it with: rustup component add llvm-tools-preview" >&2
    exit 1
fi
if ! command -v apache2 >/dev/null 2>&1; then
    echo "coverage: Apache is required for the configuration differential corpus" >&2
    exit 1
fi

rm -rf "$COVERAGE_TARGET_DIR" "$PROFILE_DIR"
mkdir -p "$PROFILE_DIR"
chmod 777 "$PROFILE_DIR"

COVERAGE_RUSTFLAGS="-C instrument-coverage -C llvm-args=-runtime-counter-relocation"
# ThinLTO rewrites coverage-instrumented Rust functions after their profile
# hashes and source mappings have been emitted. Rust 1.99 then reports those
# functions as mismatched and may discard their counters. Production releases
# retain ThinLTO; the semantically equivalent coverage build disables it so
# the measurement itself is stable.
export CARGO_PROFILE_RELEASE_LTO=false
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1

CARGO_TARGET_DIR="$COVERAGE_TARGET_DIR" RUSTFLAGS="$COVERAGE_RUSTFLAGS" \
    cargo build --release -p vapached

CARGO_TARGET_DIR="$COVERAGE_TARGET_DIR" RUSTFLAGS="$COVERAGE_RUSTFLAGS" \
LLVM_PROFILE_FILE="$PROFILE_DIR/unit-%p-%m%c.profraw" \
    cargo test -p vapached --features fault-injection -- --test-threads=1

VAPACHED="$COVERAGE_TARGET_DIR/release/vapached" \
LLVM_PROFILE_FILE="$PROFILE_DIR/vapache-%p-%m%c.profraw" \
PYTHONDONTWRITEBYTECODE=1 \
    python3 tests/config_grammar.py

VAPACHED="$COVERAGE_TARGET_DIR/release/vapached" \
LLVM_PROFILE_FILE="$PROFILE_DIR/vapache-%p-%m%c.profraw" \
PYTHONDONTWRITEBYTECODE=1 \
    python3 tests/config_validity.py

VAPACHED="$COVERAGE_TARGET_DIR/release/vapached" \
LLVM_PROFILE_FILE="$PROFILE_DIR/vapache-%p-%m%c.profraw" \
PYTHONDONTWRITEBYTECODE=1 \
    python3 tests/config_semantics.py --random 128 --seed 2469 \
        --stateful 128 --stateful-seed 1818

VAPACHED="$COVERAGE_TARGET_DIR/release/vapached" \
LLVM_PROFILE_FILE="$PROFILE_DIR/vapache-%p-%m%c.profraw" \
PYTHONDONTWRITEBYTECODE=1 \
    python3 tests/vhost_semantics.py

VAPACHED="$COVERAGE_TARGET_DIR/release/vapached" \
LLVM_PROFILE_FILE="$PROFILE_DIR/vapache-%p-%m%c.profraw" \
PYTHONDONTWRITEBYTECODE=1 \
    python3 tests/conformance.py

VAPACHED="$COVERAGE_TARGET_DIR/release/vapached" \
LLVM_PROFILE_FILE="$PROFILE_DIR/vapache-%p-%m%c.profraw" \
PYTHONDONTWRITEBYTECODE=1 \
    python3 tests/adversarial_regressions.py

# The post-processor groups raw profiles by exact binary build id before
# exporting LCOV. This avoids Rust symbol collisions between the release
# daemon, unit harnesses, integration tests, build scripts and proc macros.
SECURITY_COVERAGE_PROFILE="$PROFILE_DIR/all.profdata" \
    python3 tests/security_coverage.py --check
