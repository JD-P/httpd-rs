#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
daemon=${VAPACHE_TEST_BINARY:-$repo_root/target/debug/vapached}
case "$daemon" in
    /*) ;;
    *) daemon=$repo_root/$daemon ;;
esac
control=$repo_root/packaging/vapachectl
work=$(mktemp -d)
source_root=$work/apache2
runtime_root=$work/run
www=$work/www
port=
server_pid=

cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" >/dev/null 2>&1 || true
        wait "$server_pid" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT

if [[ $(id -u) -eq 0 && $(stat -c '%u' -- "$daemon") -ne 0 ]]; then
    install -m 0755 -- "$daemon" "$work/vapached"
    daemon=$work/vapached
fi

mkdir -p "$source_root/sites-available" "$source_root/sites-enabled" "$runtime_root" "$www"
printf 'reload fixture\n' >"$www/index.txt"
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
if [[ $(id -u) -eq 0 ]]; then
    service_uid=65534
    service_gid=65534
else
    service_uid=$(id -u)
    service_gid=$(id -g)
fi
chmod 0755 "$work" "$source_root" "$source_root/sites-available" \
    "$source_root/sites-enabled" "$runtime_root" "$www"
chmod 0644 "$www/index.txt"

cat >"$source_root/apache2.conf" <<EOF
Listen 127.0.0.1:$port
ServerName localhost
User $service_uid
Group $service_gid
PidFile $work/vapached.pid
ErrorLog $work/error.log
DocumentRoot "$www"
IncludeOptional sites-enabled/*.conf
EOF
cat >"$source_root/sites-available/access.conf" <<EOF
<Directory "$www">
    Require all denied
</Directory>
EOF
ln -s ../sites-available/access.conf "$source_root/sites-enabled/access.conf"

run_control() {
    VAPACHE_CONFDIR=$source_root \
    VAPACHE_CONFIG=$source_root/apache2.conf \
    VAPACHE_RUNTIME_DIR=$runtime_root \
    VAPACHE_SNAPSHOT_CONFIG=1 \
    VAPACHE_AUTO_CAPABILITIES=0 \
    VAPACHED=$daemon \
        "$control" "$@"
}

run_control foreground >"$work/foreground.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 100); do
    if curl --noproxy '*' --silent --output /dev/null \
        --write-out '%{http_code}' "http://127.0.0.1:$port/index.txt" \
        | grep -qx 403; then
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$work/foreground.log" >&2
        exit 1
    fi
    sleep 0.05
done
test "$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' \
    "http://127.0.0.1:$port/index.txt")" = 403

cat >"$source_root/sites-available/access.conf" <<EOF
<Directory "$www">
    Require all granted
</Directory>
EOF
run_control graceful

for _ in $(seq 1 100); do
    status=$(curl --noproxy '*' --silent --output "$work/body" \
        --write-out '%{http_code}' "http://127.0.0.1:$port/index.txt" || true)
    if [[ "$status" = 200 ]] && cmp -s "$work/body" "$www/index.txt"; then
        exit 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$work/foreground.log" >&2
        exit 1
    fi
    sleep 0.05
done

cat "$work/foreground.log" >&2
exit 1
