#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
NIGHTLY=${VAPACHE_NIGHTLY_TOOLCHAIN:-nightly}
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
        # ASan's runtime is not fork-safe. Exercise the entire library except
        # the test whose purpose is to fork a CGI worker.
        cargo +"$NIGHTLY" test -p vapached --lib --all-features \
            --target x86_64-unknown-linux-gnu -- --test-threads=1 \
            --skip cgi::tests::child_process_and_worker_main_paths
        ;;
    leak)
        # The unit-test binary intentionally owns process-global regex and
        # Loom state. Standalone integration binaries give LSan a clean exit.
        cargo +"$NIGHTLY" test -p vapached --all-features \
            --test properties --test failpoints --test fault_injection \
            --target x86_64-unknown-linux-gnu -- --test-threads=1
        ;;
    thread)
        # TSan needs an instrumented standard library and is aimed at the
        # real multi-threaded admission path; Loom explores the model space.
        cargo +"$NIGHTLY" test -Zbuild-std -p vapached --lib \
            resource::tests::concurrent_dynamic_admission_never_exceeds_the_limit \
            --target x86_64-unknown-linux-gnu -- --exact --test-threads=1
        ;;
esac
