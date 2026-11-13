#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
shim=$repo_root/packaging/httpd-rs-certbot-apachectl
deploy_hook=$repo_root/packaging/httpd-rs-certbot-deploy-hook
cleanup_helper=$repo_root/packaging/httpd-rs-certbot-cleanup
work=$(mktemp -d)
trap 'status=$?; rm -rf -- "$work"; exit "$status"' EXIT
log=$work/calls

cat >"$work/apachectl" <<'EOF'
#!/bin/sh
printf 'apache:%s\n' "$*" >>"$SHIM_TEST_LOG"
case "$1" in
    -v) echo 'Server version: Apache/2.4.66 (shim test)' ;;
    configtest) echo 'Syntax OK' ;;
esac
EOF
cat >"$work/httpd-rsctl" <<'EOF'
#!/bin/sh
printf 'httpd-rs:%s\n' "$*" >>"$SHIM_TEST_LOG"
case "$1" in
    configtest) echo 'Syntax OK' ;;
esac
EOF
cat >"$work/systemctl" <<'EOF'
#!/bin/sh
printf 'systemctl:%s\n' "$*" >>"$SHIM_TEST_LOG"
case "$1" in
    is-active) [ "${SHIM_TEST_HTTPD_RS_ACTIVE:-0}" = 1 ] ;;
esac
EOF
chmod 0755 "$work/apachectl" "$work/httpd-rsctl" "$work/systemctl"

run_shim() {
    SHIM_TEST_LOG=$log \
    HTTPD_RS_APACHECTL_DISCOVERY=$work/apachectl \
    HTTPD_RS_CONTROL=$work/httpd-rsctl \
    HTTPD_RS_SYSTEMCTL=$work/systemctl \
    HTTPD_RS_CERTBOT_TARGET=${HTTPD_RS_CERTBOT_TARGET:-httpd-rs} \
        "$shim" "$@"
}

version=$(run_shim -v)
[ "$version" = 'Server version: Apache/2.4.66 (shim test)' ]
grep -qx 'apache:-v' "$log"

: >"$log"
run_shim -t -D DUMP_MODULES
grep -qx 'apache:-t -D DUMP_MODULES' "$log"
[ "$(wc -l <"$log")" -eq 1 ]

: >"$log"
run_shim configtest >/dev/null
[ "$(sed -n '1p' "$log")" = 'apache:configtest' ]
[ "$(sed -n '2p' "$log")" = 'httpd-rs:configtest' ]
[ "$(wc -l <"$log")" -eq 2 ]

: >"$log"
HTTPD_RS_CERTBOT_TARGET=httpd-rs run_shim graceful
grep -qx 'httpd-rs:graceful' "$log"
grep -qx 'systemctl:is-active --quiet httpd-rs.service' "$log"
[ "$(wc -l <"$log")" -eq 2 ]

: >"$log"
HTTPD_RS_CERTBOT_TARGET=apache run_shim restart
grep -qx 'apache:graceful' "$log"
[ "$(wc -l <"$log")" -eq 1 ]

: >"$log"
HTTPD_RS_CERTBOT_TARGET=auto run_shim graceful
grep -qx 'systemctl:is-active --quiet httpd-rs.service' "$log"
grep -qx 'apache:graceful' "$log"
[ "$(wc -l <"$log")" -eq 2 ]

: >"$log"
HTTPD_RS_CERTBOT_TARGET=httpd-rs run_shim -k graceful
grep -qx 'httpd-rs:graceful' "$log"

: >"$log"
SHIM_TEST_HTTPD_RS_ACTIVE=1 HTTPD_RS_CERTBOT_TARGET=auto run_shim graceful
grep -qx 'systemctl:is-active --quiet httpd-rs.service' "$log"
grep -qx 'systemctl:restart httpd-rs.service' "$log"
if grep -q '^apache:graceful$\|^httpd-rs:graceful$' "$log"; then
    echo 'an active httpd-rs service must be restarted through systemd' >&2
    exit 1
fi

if run_shim launch >/dev/null 2>&1; then
    echo 'unsupported commands must fail closed' >&2
    exit 1
fi

: >"$log"
HTTPD_RS_SYSTEMCTL=$work/systemctl \
    SHIM_TEST_LOG=$log SHIM_TEST_HTTPD_RS_ACTIVE=0 \
    "$deploy_hook"
grep -qx 'systemctl:is-active --quiet httpd-rs.service' "$log"
[ "$(wc -l <"$log")" -eq 1 ]

: >"$log"
HTTPD_RS_SYSTEMCTL=$work/systemctl \
    SHIM_TEST_LOG=$log SHIM_TEST_HTTPD_RS_ACTIVE=1 \
    "$deploy_hook"
grep -qx 'systemctl:is-active --quiet httpd-rs.service' "$log"
grep -qx 'systemctl:reload httpd-rs.service' "$log"
[ "$(wc -l <"$log")" -eq 2 ]

config_root=$work/letsencrypt
mkdir -p "$config_root/renewal" "$config_root/renewal-hooks/deploy"
cat >"$config_root/cli.ini" <<'EOF'
email = admin@example.test
apache-ctl = /usr/lib/httpd-rs/certbot-apachectl
EOF
cat >"$config_root/renewal/example.test.conf" <<'EOF'
[renewalparams]
authenticator = apache
apache_ctl = /usr/lib/httpd-rs/certbot-apachectl
EOF
ln -s /usr/lib/httpd-rs/certbot-deploy-hook \
    "$config_root/renewal-hooks/deploy/httpd-rs-reload"
HTTPD_RS_CERTBOT_CONFIG_ROOT=$config_root "$cleanup_helper"
grep -qx 'email = admin@example.test' "$config_root/cli.ini"
! grep -q 'apache-ctl' "$config_root/cli.ini"
grep -qx 'authenticator = apache' "$config_root/renewal/example.test.conf"
! grep -q 'apache_ctl' "$config_root/renewal/example.test.conf"
[ ! -e "$config_root/renewal-hooks/deploy/httpd-rs-reload" ]
[ ! -L "$config_root/renewal-hooks/deploy/httpd-rs-reload" ]

echo 'certbot Apache control shim: pass'
