#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

docker_cmd=(
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS
    -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH
    docker --host=unix:///var/run/docker.sock
)
image=${HTTPD_RS_CHAOS_IMAGE:-httpd-rs-chaos:local}

if [[ ${CHAOS_SKIP_BUILD:-0} != 1 ]]; then
    cargo build --locked --release -p httpd-rs
fi

"${docker_cmd[@]}" build --file tests/chaos/Dockerfile --tag "$image" .

common=(
    run --rm
    --read-only
    --tmpfs /tmp:rw,nosuid,nodev,size=128m
    --network none
    --memory 256m
    --memory-swap 256m
    --pids-limit 128
    --cpus 1
    --ulimit nofile=256:256
    --security-opt no-new-privileges=true
    --cap-drop ALL
    --cap-add CHOWN
    --cap-add DAC_OVERRIDE
    --cap-add KILL
    --cap-add SETGID
    --cap-add SETUID
    --env CHAOS_SOAK_SECONDS
    --env CHAOS_SOAK_WORKERS
    --mount "type=bind,src=$repo_root,dst=/workspace,readonly"
    --workdir /workspace
)

"${docker_cmd[@]}" "${common[@]}" "$image" resources
"${docker_cmd[@]}" "${common[@]}" --cap-add SYS_PTRACE "$image" syscalls
"${docker_cmd[@]}" "${common[@]}" "$image" broker
