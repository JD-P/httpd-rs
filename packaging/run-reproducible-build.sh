#!/bin/bash -p
set -euo pipefail

LC_ALL=C
export LC_ALL
unset CDPATH ENV BASH_ENV
umask 022

for command in docker git; do
    command -v "$command" >/dev/null || {
        echo "reproducible-builder: missing required command: $command" >&2
        exit 1
    }
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
source_date_epoch=${SOURCE_DATE_EPOCH:-$(git -C "$repo_root" log -1 --format=%ct)}
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || {
    echo "reproducible-builder: SOURCE_DATE_EPOCH must be a non-negative integer" >&2
    exit 1
}

image=vapache-reproducible-builder:rust-1.99.1-debian-20261104
build_secrets=()
if [[ -n "${CODEX_PROXY_CERT:-}" && -r "$CODEX_PROXY_CERT" ]]; then
    build_secrets+=(--secret "id=proxy_ca,src=$CODEX_PROXY_CERT")
fi
docker build \
    "${build_secrets[@]}" \
    --file "$script_dir/reproducible-builder.Dockerfile" \
    --tag "$image" \
    "$repo_root"

# Use the caller's uid/gid so release files remain manageable outside CI.
# Cargo's immutable cache is copied into private scratch space because Cargo
# takes a package-cache lock even during an offline build. The image's cache is
# root-owned and some crates intentionally preserve group-only source modes, so
# a fixed root prelude copies and transfers it before dropping all privileges.
docker run --rm --network none \
    --env CARGO_NET_OFFLINE=true \
    --env HOME=/tmp \
    --env SOURCE_DATE_EPOCH="$source_date_epoch" \
    --env VAPACHE_BUILD_UID="$(id -u)" \
    --env VAPACHE_BUILD_GID="$(id -g)" \
    --mount "type=bind,src=$repo_root,dst=/src" \
    --workdir /src \
    "$image" \
    bash -c '
        set -euo pipefail
        cp -a /usr/local/cargo /tmp/cargo-home
        chown -R "$VAPACHE_BUILD_UID:$VAPACHE_BUILD_GID" /tmp/cargo-home
        exec setpriv \
            --reuid="$VAPACHE_BUILD_UID" \
            --regid="$VAPACHE_BUILD_GID" \
            --clear-groups \
            env CARGO_HOME=/tmp/cargo-home \
            /src/tests/reproducible_build.sh "$@"
    ' bash "$@"
