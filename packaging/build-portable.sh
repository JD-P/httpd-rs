#!/bin/bash -p
set -euo pipefail

LC_ALL=C
TZ=UTC
export LC_ALL TZ
unset CDPATH ENV BASH_ENV RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
umask 022

usage() {
    echo "Usage: $0 [--target TARGET] --target-dir DIR" >&2
    exit 2
}

target=x86_64-unknown-linux-musl
target_dir=
while (($#)); do
    case "$1" in
        --target)
            (($# >= 2)) || usage
            target=$2
            shift 2
            ;;
        --target-dir)
            (($# >= 2)) || usage
            target_dir=$2
            shift 2
            ;;
        *) usage ;;
    esac
done

[[ -n "$target_dir" ]] || usage
[[ "$target" =~ ^[A-Za-z0-9_.-]+$ ]] || {
    echo "portable-build: invalid target: $target" >&2
    exit 1
}

source_date_epoch=${SOURCE_DATE_EPOCH:-0}
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || {
    echo "portable-build: SOURCE_DATE_EPOCH must be a non-negative integer" >&2
    exit 1
}
export SOURCE_DATE_EPOCH="$source_date_epoch"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
mkdir -p -- "$target_dir"
target_dir=$(cd -- "$target_dir" && pwd -P)

# Cargo passes these flags to every crate, including dependencies. Remapping
# both project and tool-cache paths makes panic locations and other embedded
# paths independent of the checkout and runner layout. CARGO_ENCODED_RUSTFLAGS
# preserves paths containing spaces without relying on shell word splitting.
encoded_rustflags="--remap-path-prefix=$repo_root=/usr/src/vapache"
encoded_rustflags+=$'\x1f'"--remap-path-prefix=$target_dir=/usr/src/vapache/target"
if [[ -n "${CARGO_HOME:-}" ]]; then
    cargo_home=$CARGO_HOME
elif [[ -n "${HOME:-}" ]]; then
    cargo_home=$HOME/.cargo
else
    cargo_home=
fi
if [[ -d "$cargo_home" ]]; then
    cargo_home=$(cd -- "$cargo_home" && pwd -P)
    encoded_rustflags+=$'\x1f'"--remap-path-prefix=$cargo_home=/usr/local/cargo"
fi
if [[ -n "${RUSTUP_HOME:-}" ]]; then
    rustup_home=$RUSTUP_HOME
elif [[ -n "${HOME:-}" ]]; then
    rustup_home=$HOME/.rustup
else
    rustup_home=
fi
if [[ -d "$rustup_home" ]]; then
    rustup_home=$(cd -- "$rustup_home" && pwd -P)
    encoded_rustflags+=$'\x1f'"--remap-path-prefix=$rustup_home=/usr/local/rustup"
fi
encoded_rustflags+=$'\x1f-C\x1flink-arg=-Wl,--build-id=sha1'
export CARGO_ENCODED_RUSTFLAGS="$encoded_rustflags"
export CARGO_INCREMENTAL=0

if [[ "$target" == x86_64-unknown-linux-musl ]]; then
    command -v musl-gcc >/dev/null || {
        echo "portable-build: musl-gcc is required for $target" >&2
        exit 1
    }
    export CC_x86_64_unknown_linux_musl=musl-gcc
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
fi

cd -- "$repo_root"
CARGO_TARGET_DIR="$target_dir" \
    cargo build --locked --release -p vapached --target "$target"

printf 'portable-build: wrote %s\n' "$target_dir/$target/release/vapached"
