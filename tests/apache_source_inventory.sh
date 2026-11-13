#!/bin/sh
# Reproduce the checked-in Apache source inventory from its pinned release.
# "--update" writes only the observational manifest.  It intentionally does
# not acknowledge the new digest or change compatibility claims; that review
# remains a separate, visible policy edit.
set -eu

cd "$(dirname "$0")/.."

MODE=check
if [ "${1:-}" = "--update" ]; then
    MODE=update
    shift
fi
if [ "$#" -ne 0 ]; then
    echo "usage: tests/apache_source_inventory.sh [--update]" >&2
    exit 2
fi

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
WORK=$(mktemp -d /tmp/vapache-apache-source.XXXXXX)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
ARCHIVE=$WORK/httpd.tar.bz2
TEST_URL=$(read_test_pin archive_url)
TEST_EXPECTED=$(read_test_pin archive_sha256)
TEST_COMMIT=$(read_test_pin commit)
TEST_ARCHIVE=$WORK/httpd-tests.tar.gz
FRAMEWORK_URL=$(read_test_pin submodules.Apache-Test.archive_url)
FRAMEWORK_EXPECTED=$(read_test_pin submodules.Apache-Test.archive_sha256)
FRAMEWORK_COMMIT=$(read_test_pin submodules.Apache-Test.commit)
FRAMEWORK_ARCHIVE=$WORK/perl-apache-test.tar.gz

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
test -d "$SOURCE/server" || {
    echo "apache-source-inventory: archive does not contain httpd-$RELEASE" >&2
    exit 1
}
test -d "$TEST_SOURCE/t" || {
    echo "apache-source-inventory: test archive does not contain httpd-tests-$TEST_COMMIT" >&2
    exit 1
}
test -d "$FRAMEWORK_SOURCE/lib" || {
    echo "apache-source-inventory: framework archive does not contain perl-apache-test-$FRAMEWORK_COMMIT" >&2
    exit 1
}
cp -R "$FRAMEWORK_SOURCE"/. "$TEST_SOURCE/Apache-Test/"

if [ "$MODE" = update ]; then
    python3 tests/apache_warrant.py \
        --source "$SOURCE" \
        --httpd-tests-source "$TEST_SOURCE" \
        --write-manifest
    NEW_HASH=$(python3 - <<'PY'
import json
from pathlib import Path
print(json.loads(Path("docs/apache-source-manifest.json").read_text())["inventory_sha256"])
PY
)
    echo "apache-source-inventory: inspect the manifest diff" >&2
    echo "apache-source-inventory: then explicitly set acknowledged_inventory_sha256 to $NEW_HASH" >&2
    echo "apache-source-inventory: no support claim was added" >&2
else
    python3 tests/apache_warrant.py \
        --source "$SOURCE" \
        --httpd-tests-source "$TEST_SOURCE" \
        --check-source
    python3 tests/apache_warrant.py
fi
