#!/bin/bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
control=$repo_root/packaging/httpd-rsctl
deploy_hook=$repo_root/packaging/httpd-rs-certbot-deploy-hook
service_unit=$repo_root/packaging/httpd-rs.service
work=$(mktemp -d)
trap 'rm -rf --one-file-system -- "$work"' EXIT

# systemd implements RestrictSUIDSGID by making openat2 return ENOSYS. That
# breaks httpd-rs's mandatory descriptor-contained resolver before configtest.
# Keep the compatible service hardening explicit and reject the known-bad
# combination without waiting for the slower package/systemd integration job.
if grep -qx 'RestrictSUIDSGID=true' "$service_unit"; then
    echo 'httpd-rs.service blocks its own mandatory openat2 resolver' >&2
    exit 1
fi
grep -qx 'NoNewPrivileges=true' "$service_unit"
grep -qx 'SystemCallArchitectures=native' "$service_unit"

fake_daemon=$work/httpd-rs
cat >"$fake_daemon" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$HTTPD_RS_FAKE_LOG"
sleep "${HTTPD_RS_FAKE_SLEEP:-0}"
exit 0
EOF
chmod 0755 "$fake_daemon"

run_control() {
    source_root=$1
    runtime_root=$2
    shift 2
    HTTPD_RS_CONFDIR=$source_root \
    HTTPD_RS_CONFIG=$source_root/apache2.conf \
    HTTPD_RS_RUNTIME_DIR=$runtime_root \
    HTTPD_RS_SNAPSHOT_CONFIG=1 \
    HTTPD_RS_AUTO_CAPABILITIES=0 \
    HTTPD_RS=$fake_daemon \
    HTTPD_RS_FAKE_LOG=$work/daemon-calls \
        "$control" "$@"
}

make_config() {
    mkdir -p "$1/sites-enabled"
    printf '%s\n' 'ServerName control.test' >"$1/apache2.conf"
    chmod 0755 "$1" "$1/sites-enabled"
    chmod 0644 "$1/apache2.conf"
}

# A controlled leaf below an attacker-controlled ancestor used to pass the
# recursive tree check, leaving a rename window between validation and copy.
untrusted_parent=$work/untrusted-parent
untrusted_root=$untrusted_parent/apache2
make_config "$untrusted_root"
chmod 0777 "$untrusted_parent"
mkdir -m 0755 "$work/untrusted-run"
: >"$work/daemon-calls"
if run_control "$untrusted_root" "$work/untrusted-run" configtest \
    >"$work/untrusted.out" 2>&1; then
    echo 'httpd-rsctl accepted a configuration below an untrusted ancestor' >&2
    exit 1
fi
grep -q 'ancestor is not caller-controlled' "$work/untrusted.out"
test ! -s "$work/daemon-calls"

# Snapshotting must never copy a FIFO, device, socket, or dangling link. Such
# an entry could otherwise block a privileged cp or later configuration read.
special_root=$work/special/apache2
make_config "$special_root"
mkfifo "$special_root/config.pipe"
mkdir -m 0755 "$work/special-run"
: >"$work/daemon-calls"
if run_control "$special_root" "$work/special-run" configtest \
    >"$work/special.out" 2>&1; then
    echo 'httpd-rsctl accepted a special configuration-tree entry' >&2
    exit 1
fi
grep -q 'special or dangling file' "$work/special.out"
test ! -s "$work/daemon-calls"

# Containment is checked before any recursive dereference, so an escaping link
# cannot make the privileged ownership walk traverse /proc or another mount.
escape_root=$work/escape/apache2
make_config "$escape_root"
ln -s /proc "$escape_root/large-external-tree"
mkdir -m 0755 "$work/escape-run"
: >"$work/daemon-calls"
if run_control "$escape_root" "$work/escape-run" configtest \
    >"$work/escape.out" 2>&1; then
    echo 'httpd-rsctl accepted an escaping configuration symlink' >&2
    exit 1
fi
grep -q 'configuration symlink escapes' "$work/escape.out"
test ! -s "$work/daemon-calls"

# Runtime paths are mutation targets. Refuse a symlink even when its target is
# otherwise controlled.
safe_root=$work/safe/apache2
make_config "$safe_root"
mkdir -m 0755 "$work/actual-run"
ln -s "$work/actual-run" "$work/runtime-link"
: >"$work/daemon-calls"
if run_control "$safe_root" "$work/runtime-link" configtest \
    >"$work/runtime-link.out" 2>&1; then
    echo 'httpd-rsctl accepted a symlinked runtime directory' >&2
    exit 1
fi
grep -q 'runtime directory must be canonical' "$work/runtime-link.out"
test ! -s "$work/daemon-calls"

# Two control invocations must serialize their fixed-name snapshot swap.
mkdir -m 0755 "$work/concurrent-run"
: >"$work/daemon-calls"
HTTPD_RS_FAKE_SLEEP=0.15 run_control \
    "$safe_root" "$work/concurrent-run" configtest &
first_pid=$!
HTTPD_RS_FAKE_SLEEP=0.15 run_control \
    "$safe_root" "$work/concurrent-run" configtest &
second_pid=$!
wait "$first_pid"
wait "$second_pid"
test "$(wc -l <"$work/daemon-calls")" -eq 2
test -f "$work/concurrent-run/apache-config/apache2.conf"
test ! -e "$work/concurrent-run/.apache-config.previous"
test -z "$(find "$work/concurrent-run" -maxdepth 1 -name '.apache-config.*' -print -quit)"

# Privileged hooks establish their own PATH before the first external command.
hostile=$work/hostile
mkdir -m 0755 "$hostile"
cat >"$hostile/systemctl" <<EOF
#!/bin/sh
printf 'executed\n' >>"$work/hostile-executed"
exit 0
EOF
chmod 0755 "$hostile/systemctl"
cat >"$hostile/startup" <<EOF
printf 'startup\n' >>"$work/hostile-startup-executed"
EOF
PATH="$hostile" ENV="$hostile/startup" BASH_ENV="$hostile/startup" \
    "$deploy_hook"
test ! -e "$work/hostile-executed"
test ! -e "$work/hostile-startup-executed"

# An explicit override is accepted only when both the command and its complete
# path are controlled. Ownership of the leaf alone is insufficient.
attacker_parent=$work/attacker-bin
mkdir -m 0755 "$attacker_parent"
cp "$hostile/systemctl" "$attacker_parent/systemctl"
chmod 0777 "$attacker_parent"
if HTTPD_RS_SYSTEMCTL=$attacker_parent/systemctl "$deploy_hook" \
    >"$work/override.out" 2>&1; then
    echo 'deploy hook accepted a command below an untrusted ancestor' >&2
    exit 1
fi
grep -q 'unsafe HTTPD_RS_SYSTEMCTL' "$work/override.out"
test ! -e "$work/hostile-executed"

if HTTPD_RS_SYSTEMCTL=/bin/sh "$deploy_hook" \
    >"$work/interpreter.out" 2>&1; then
    echo 'deploy hook accepted a general-purpose interpreter as systemctl' >&2
    exit 1
fi
grep -q 'unsafe HTTPD_RS_SYSTEMCTL' "$work/interpreter.out"

echo 'privileged control-plane security: pass'
