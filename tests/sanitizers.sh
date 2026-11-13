#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
NIGHTLY=${HTTPD_RS_NIGHTLY_TOOLCHAIN:-nightly}
sanitizer=${1:-address}
case "$sanitizer" in
    address|leak|thread) ;;
    *) echo "sanitizers: expected address, leak, or thread" >&2; exit 2 ;;
esac

export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Zsanitizer=$sanitizer -Cdebuginfo=1"
export RUSTDOCFLAGS="${RUSTDOCFLAGS:+$RUSTDOCFLAGS }-Zsanitizer=$sanitizer"
export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0:strict_string_checks=1:check_initialization_order=1}
export LSAN_OPTIONS=${LSAN_OPTIONS:-report_objects=1}
export TSAN_OPTIONS=${TSAN_OPTIONS:-halt_on_error=1:second_deadlock_stack=1}

case "$sanitizer" in
    address)
        # First exercise every audited syscall wrapper with the smallest
        # possible instrumented binary, then the server's composed paths.
        cargo +"$NIGHTLY" test -p httpd-rs-os \
            --target x86_64-unknown-linux-gnu -- --test-threads=1
        # ASan's runtime is not fork-safe and its overhead intentionally
        # violates one wall-clock progress test. Exclude only those probes;
        # their syscall cores run in the dedicated crate above and in the
        # ordinary/weekly suites.
        cargo +"$NIGHTLY" test -p httpd-rs --lib --all-features \
            --target x86_64-unknown-linux-gnu -- --test-threads=1 \
            --skip cgi::tests::child_process_and_worker_main_paths \
            --skip h2::tests::progressing_h2_response_outlives_the_idle_and_send_intervals \
            --skip rewrite::tests::maps_backrefs_and_url_helpers \
            --skip rewrite::tests::prg_descriptor_isolation_subprocess \
            --skip tls::tests::privileged_broker_reports_ready_only_after_descriptor_isolation
        ;;
    leak)
        # The unit-test binary intentionally owns process-global regex and
        # Loom state. Standalone integration binaries give LSan a clean exit.
        cargo +"$NIGHTLY" test -p httpd-rs-os \
            --target x86_64-unknown-linux-gnu -- --test-threads=1
        cargo +"$NIGHTLY" test -p httpd-rs --all-features \
            --test properties --test failpoints --test fault_injection \
            --target x86_64-unknown-linux-gnu -- --test-threads=1
        ;;
    thread)
        # TSan needs an instrumented standard library and is aimed at the
        # real multi-threaded admission path; Loom explores the model space.
        cargo +"$NIGHTLY" test -Zbuild-std -p httpd-rs --lib \
            resource::tests::concurrent_dynamic_admission_never_exceeds_the_limit \
            --target x86_64-unknown-linux-gnu -- --exact --test-threads=1
        cargo +"$NIGHTLY" test -Zbuild-std -p httpd-rs-pcre2 \
            --test concurrency --target x86_64-unknown-linux-gnu -- \
            --test-threads=1
        ;;
esac
