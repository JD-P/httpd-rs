#!/bin/sh
# Fail-closed release gate for the next adversarial pass. This includes the
# real PHP-FPM P17/P18 batteries; missing external dependencies are failures,
# never silent skips.
set -eu

cd "$(dirname "$0")/.."
REPO_ROOT=$PWD
LOCAL_SETUP=$(dirname "$REPO_ROOT")/.httpd-rs-setup
NIGHTLY=${HTTPD_RS_NIGHTLY_TOOLCHAIN:-nightly}

PATH="$REPO_ROOT/../verus-bin:$REPO_ROOT/../.cargo/bin:$PATH"
export PATH

fail() {
    echo "pre-adversarial: $*" >&2
    exit 2
}

step() {
    echo "pre-adversarial: $*"
}

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v cargo-verus >/dev/null 2>&1 || fail "cargo-verus is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
cargo +"$NIGHTLY" --version >/dev/null 2>&1 || fail "a nightly Rust toolchain is required for cargo-fuzz"
cargo +"$NIGHTLY" fuzz --version >/dev/null 2>&1 || fail "cargo-fuzz is required"

if [ -n "${APACHE:-}" ]; then
    [ -x "$APACHE" ] || fail "APACHE is not executable: $APACHE"
elif command -v apache2 >/dev/null 2>&1; then
    APACHE=$(command -v apache2)
elif [ -x "$LOCAL_SETUP/bin/apache2" ]; then
    APACHE=$LOCAL_SETUP/bin/apache2
else
    fail "Apache httpd is required"
fi
PATH="$(dirname "$APACHE"):$PATH"
export PATH APACHE

if [ -z "${APACHE_MODDIR:-}" ]; then
    if [ -d /usr/lib/apache2/modules ]; then
        APACHE_MODDIR=/usr/lib/apache2/modules
    elif [ -d "$LOCAL_SETUP/sysroot/usr/lib/apache2/modules" ]; then
        APACHE_MODDIR=$LOCAL_SETUP/sysroot/usr/lib/apache2/modules
    else
        fail "Apache module directory is required"
    fi
fi
[ -f "$APACHE_MODDIR/mod_proxy_fcgi.so" ] \
    || fail "mod_proxy_fcgi.so is missing from $APACHE_MODDIR"
export APACHE_MODDIR

if [ -n "${PHP_FPM:-}" ]; then
    [ -x "$PHP_FPM" ] || fail "PHP_FPM is not executable: $PHP_FPM"
else
    PHP_FPM=
    for candidate in \
        /usr/sbin/php-fpm8.4 \
        /usr/sbin/php-fpm8.3 \
        /usr/sbin/php-fpm8.2 \
        /usr/sbin/php-fpm \
        "$LOCAL_SETUP"/sysroot/usr/sbin/php-fpm*; do
        if [ -x "$candidate" ]; then
            PHP_FPM=$candidate
            break
        fi
    done
    [ -n "$PHP_FPM" ] || fail "a real PHP-FPM executable is required"
fi
export PHP_FPM

LOCAL_LIB=$LOCAL_SETUP/sysroot/usr/lib/x86_64-linux-gnu
if [ -d "$LOCAL_LIB" ]; then
    LD_LIBRARY_PATH=$LOCAL_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
    export LD_LIBRARY_PATH
fi

HTTPD_RS=$REPO_ROOT/target/release/httpd-rs
export HTTPD_RS
export PYTHONDONTWRITEBYTECODE=1

step "release build"
cargo build --release -p httpd-rs

step "executable documentation"
python3 tests/docs.py

step "Apache source warrant and binary-oracle closure"
python3 tests/apache_warrant.py
python3 tests/apache_configuration_warrant.py
python3 tests/apache_warrant.py --check-binary

step "Rust workspace tests"
cargo test --workspace -- --test-threads=1

step "coverage-guided parser fuzz targets"
tests/fuzz_smoke.sh

step "Verus proof and verification-ledger gate"
python3 tests/resource_inventory.py
python3 tests/resource_warrant.py
python3 tests/resource_profile_selftest.py
python3 tests/verification_status.py --run-verus

step "configuration grammar and validity differentials"
python3 tests/config_grammar.py
python3 tests/config_validity.py

step "fixed, randomized, and stateful configuration semantics"
python3 tests/config_semantics.py \
    --random 300 --seed 2469 \
    --stateful 256 --stateful-seed 1818

step "multi-vhost configuration isolation and reload semantics"
python3 tests/vhost_semantics.py

step "end-to-end Apache differential conformance"
python3 tests/conformance.py --differential

step "generated transform and sink differential"
python3 tests/transform_differential.py

step "P34 decoded synthesized-identity differential"
P34_APACHE="$APACHE" P34_APACHE_MODULES="$APACHE_MODDIR" \
    python3 adversarial/p34/exploit_p34.py

step "P36 trailing-slash rewrite process-survival differential"
P36_APACHE="$APACHE" P36_APACHE_MODULES="$APACHE_MODDIR" \
    python3 adversarial/p36/exploit_p36.py

step "attacker-view information-disclosure noninterference"
python3 tests/information_disclosure.py --all-probes

step "portable adversarial regressions"
python3 tests/adversarial_regressions.py

step "real PHP-FPM P17 battery"
python3 adversarial/p17/exploit_p17.py

step "real PHP-FPM/CGI P18 battery"
python3 adversarial/p18/exploit_p18.py

step "PASS"
