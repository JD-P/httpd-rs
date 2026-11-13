#!/usr/bin/env bash
# Build the pinned Apache oracle with GCC branch coverage, drive the existing
# differential corpus through it, and group uncovered branches by warrant
# family. Intended for the weekly deep-quality runner.
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

for tool in curl sha256sum tar gcc make gcov gcovr; do
    command -v "$tool" >/dev/null || {
        echo "apache-source-coverage: missing required tool: $tool" >&2
        exit 2
    }
done

read_pin() {
    python3 - "$1" <<'PY'
import json
import sys
from pathlib import Path
policy = json.loads(Path("docs/apache-warrant-policy.json").read_text())
print(policy["source_pin"][sys.argv[1]])
PY
}


read_test_pin() {
    python3 - "$1" <<'PY'
import json
import sys
from pathlib import Path
policy = json.loads(Path("docs/apache-warrant-policy.json").read_text())
value = policy["upstream_test_pin"]
for part in sys.argv[1].split("."):
    value = value[part]
print(value)
PY
}

URL=$(read_pin archive_url)
EXPECTED=$(read_pin archive_sha256)
RELEASE=$(read_pin release)
WORK=${APACHE_COVERAGE_WORK:-$(mktemp -d /tmp/vapache-apache-coverage.XXXXXX)}
KEEP=${APACHE_COVERAGE_KEEP:-0}
if [[ $KEEP != 1 ]]; then
    trap 'rm -rf "$WORK"' EXIT HUP INT TERM
fi
mkdir -p "$WORK"
ARCHIVE=$WORK/httpd.tar.bz2
TEST_URL=$(read_test_pin archive_url)
TEST_EXPECTED=$(read_test_pin archive_sha256)
TEST_COMMIT=$(read_test_pin commit)
TEST_ARCHIVE=$WORK/httpd-tests.tar.gz
FRAMEWORK_URL=$(read_test_pin submodules.Apache-Test.archive_url)
FRAMEWORK_EXPECTED=$(read_test_pin submodules.Apache-Test.archive_sha256)
FRAMEWORK_COMMIT=$(read_test_pin submodules.Apache-Test.commit)
FRAMEWORK_ARCHIVE=$WORK/perl-apache-test.tar.gz
PREFIX=$WORK/install
REPORT_DIR=${APACHE_COVERAGE_REPORT_DIR:-$PWD/artifacts/apache-source-coverage}
mkdir -p "$REPORT_DIR"

curl --fail --location --retry 3 "$URL" -o "$ARCHIVE"
printf '%s  %s\n' "$EXPECTED" "$ARCHIVE" | sha256sum --check -
curl --fail --location --retry 3 "$TEST_URL" -o "$TEST_ARCHIVE"
printf '%s  %s\n' "$TEST_EXPECTED" "$TEST_ARCHIVE" | sha256sum --check -
curl --fail --location --retry 3 "$FRAMEWORK_URL" -o "$FRAMEWORK_ARCHIVE"
printf '%s  %s\n' "$FRAMEWORK_EXPECTED" "$FRAMEWORK_ARCHIVE" | sha256sum --check -
tar -xjf "$ARCHIVE" -C "$WORK"
tar -xzf "$TEST_ARCHIVE" -C "$WORK"
tar -xzf "$FRAMEWORK_ARCHIVE" -C "$WORK"
SOURCE=$WORK/httpd-$RELEASE
TEST_SOURCE=$WORK/httpd-tests-$TEST_COMMIT
FRAMEWORK_SOURCE=$WORK/perl-apache-test-$FRAMEWORK_COMMIT
test -d "$SOURCE/server" && test -d "$TEST_SOURCE/t" && test -d "$FRAMEWORK_SOURCE/lib" || {
    echo "apache-source-coverage: a pinned archive has an unexpected layout" >&2
    exit 1
}
cp -R "$FRAMEWORK_SOURCE"/. "$TEST_SOURCE/Apache-Test/"
python3 tests/apache_warrant.py \
    --source "$SOURCE" \
    --httpd-tests-source "$TEST_SOURCE" \
    --check-source

module_args=(
    # Match the Debian oracle's compiled-in control modules. The differential
    # fixtures intentionally do not LoadModule these baseline commands.
    --enable-watchdog=static
    --enable-log-config=static
    --enable-logio=static
    --enable-version=static
    --enable-unixd=static
    --enable-mime=shared
    --enable-dir=shared
    --enable-alias=shared
    --enable-autoindex=shared
    --enable-authz-core=shared
    --enable-authz-host=shared
    --enable-access-compat=shared
    --enable-allowmethods=shared
    --enable-headers=shared
    --enable-env=shared
    --enable-setenvif=shared
    --enable-auth-basic=shared
    --enable-authn-core=shared
    --enable-authn-file=shared
    --enable-authz-user=shared
    --enable-authz-groupfile=shared
    --enable-rewrite=shared
    --enable-proxy=shared
    --enable-proxy-balancer=shared
    --enable-proxy-hcheck=shared
    --enable-proxy-http=shared
    --enable-proxy-fcgi=shared
    --enable-expires=shared
    --enable-filter=shared
    --enable-deflate=shared
    --enable-brotli=shared
    --enable-reqtimeout=shared
    --enable-remoteip=shared
    --enable-cache=shared
    --enable-cache-disk=shared
    --enable-socache-shmcb=shared
    --enable-ssl=shared
    --enable-cgi=shared
    --enable-http2=shared
    --enable-negotiation=shared
    --enable-status=shared
)

(
    cd "$SOURCE"
    CFLAGS="-O0 -g --coverage" LDFLAGS="--coverage" \
        ./configure \
            --prefix="$PREFIX" \
            --enable-so \
            --with-mpm=event \
            --enable-mpms-shared=event \
            "${module_args[@]}"
    make -j"${APACHE_COVERAGE_JOBS:-2}"
    make install
)

cargo build --locked --release -p vapached
export APACHE=$PREFIX/bin/httpd
export APACHE_MODDIR=$PREFIX/modules
export VAPACHED=$PWD/target/release/vapached
export PYTHONDONTWRITEBYTECODE=1

python3 tests/apache_warrant.py --check-binary
python3 tests/config_grammar.py
python3 tests/config_validity.py
python3 tests/config_semantics.py --random 64 --seed 2469 --stateful 64 --stateful-seed 1818
python3 tests/conformance.py --differential

gcovr \
    --root "$SOURCE" \
    --filter "$SOURCE/server/" \
    --filter "$SOURCE/modules/" \
    --json "$REPORT_DIR/apache-gcov.json"
python3 tests/apache_source_coverage.py \
    "$REPORT_DIR/apache-gcov.json" \
    --source "$SOURCE" \
    --output "$REPORT_DIR/family-summary.json" \
    >"$REPORT_DIR/family-summary.stdout.json"

echo "apache-source-coverage: reports written to $REPORT_DIR"
if [[ $KEEP == 1 ]]; then
    echo "apache-source-coverage: retained build tree at $WORK"
fi
