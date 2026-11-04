#!/bin/bash -p
set -euo pipefail

LC_ALL=C
TZ=UTC
export LC_ALL TZ
unset CDPATH ENV BASH_ENV
umask 022

usage() {
    echo "Usage: $0 [--target TARGET] [--output DIR]" >&2
    exit 2
}

target=x86_64-unknown-linux-musl
output=
while (($#)); do
    case "$1" in
        --target)
            (($# >= 2)) || usage
            target=$2
            shift 2
            ;;
        --output)
            (($# >= 2)) || usage
            output=$2
            shift 2
            ;;
        *) usage ;;
    esac
done

[[ "$target" == x86_64-unknown-linux-musl ]] || {
    echo "reproducible-build: package layout requires x86_64-unknown-linux-musl" >&2
    exit 1
}

for command in cargo dpkg-deb gzip musl-gcc python3 readelf rpmbuild sha256sum tar; do
    command -v "$command" >/dev/null || {
        echo "reproducible-build: missing required command: $command" >&2
        exit 1
    }
done

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    SOURCE_DATE_EPOCH=$(git -C "$repo_root" log -1 --format=%ct)
fi
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || {
    echo "reproducible-build: SOURCE_DATE_EPOCH must be a non-negative integer" >&2
    exit 1
}
export SOURCE_DATE_EPOCH

work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT INT TERM

copy_source() {
    local destination=$1
    mkdir -p -- "$destination"
    tar -C "$repo_root" \
        --exclude='./.git' \
        --exclude='./target' \
        --exclude='./release' \
        --exclude='*/target' \
        -cf - . | tar -C "$destination" -xf -
}

build_once() {
    local source_root=$1
    local target_root=$2
    local artifact_root=$3
    local version

    "$source_root/packaging/build-portable.sh" \
        --target "$target" \
        --target-dir "$target_root"
    version=$(cargo metadata \
        --manifest-path "$source_root/Cargo.toml" \
        --locked --no-deps --format-version 1 \
        | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "vapached"))')
    "$source_root/packaging/build-linux-packages.sh" \
        --binary "$target_root/$target/release/vapached" \
        --version "$version" \
        --output "$artifact_root"
}

source_a="$work_dir/source-a"
source_b="$work_dir/a-deliberately-different-source-path/source-b"
target_a="$work_dir/target-a"
target_b="$work_dir/a-deliberately-different-target-path/target-b"
artifacts_a="$work_dir/artifacts-a"
artifacts_b="$work_dir/artifacts-b"
copy_source "$source_a"
copy_source "$source_b"

build_once "$source_a" "$target_a" "$artifacts_a"
# The packaged artifact set is self-contained. Keeping the first Cargo target
# tree while compiling the second copy only doubles peak disk consumption and
# does not strengthen the byte-for-byte comparison below.
rm -rf -- "$target_a"
build_once "$source_b" "$target_b" "$artifacts_b"

(
    cd -- "$artifacts_a"
    sha256sum -- * | sort -k2
) >"$work_dir/hashes-a"
(
    cd -- "$artifacts_b"
    sha256sum -- * | sort -k2
) >"$work_dir/hashes-b"

if ! diff -u "$work_dir/hashes-a" "$work_dir/hashes-b"; then
    echo "reproducible-build: release artifact hashes differ" >&2
    exit 1
fi

if [[ -n "$output" ]]; then
    mkdir -p -- "$output"
    output=$(cd -- "$output" && pwd -P)
    if [[ -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        echo "reproducible-build: output directory is not empty: $output" >&2
        exit 1
    fi
    cp -a -- "$artifacts_a"/. "$output"/
fi

echo "reproducible-build: complete release set is byte-for-byte identical"
cat "$work_dir/hashes-a"
