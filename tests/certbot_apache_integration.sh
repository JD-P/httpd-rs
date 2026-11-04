#!/usr/bin/env bash
set -euo pipefail

if (($# != 1)); then
    echo "Usage: $0 VAPACHE.deb" >&2
    exit 2
fi

package=$(realpath -- "$1")
[[ -f "$package" ]] || {
    echo "Certbot integration package does not exist: $package" >&2
    exit 1
}

mounts=(-v "$(dirname -- "$package"):/release:ro")
override=0
if [[ -n "${VAPACHE_TEST_BINARY:-}" ]]; then
    test_binary=$(realpath -- "$VAPACHE_TEST_BINARY")
    [[ -x "$test_binary" ]] || {
        echo "VAPACHE_TEST_BINARY is not executable: $test_binary" >&2
        exit 1
    }
    mounts+=(-v "$test_binary:/current/vapached:ro")
    override=1
fi

docker run --rm -i "${mounts[@]}" debian:13-slim bash -s -- \
    "$(basename -- "$package")" "$override" <<'CONTAINER'
set -euo pipefail

package_name=$1
override=$2
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null
apt-get install -y --no-install-recommends \
    apache2 certbot python3-certbot-apache curl openssl >/dev/null

printf '%s\n' \
    '<VirtualHost *:80>' \
    'ServerName example.test' \
    'DocumentRoot /var/www/html' \
    '<Directory /var/www/html>' \
    'Require all granted' \
    '</Directory>' \
    '</VirtualHost>' \
    >/etc/apache2/sites-available/example.test.conf
a2ensite example.test >/dev/null
dpkg -i "/release/$package_name" >/dev/null
if [[ "$override" == 1 ]]; then
    install -m 0755 /current/vapached /usr/sbin/vapached
fi

chmod 0666 /usr/lib/vapache/control-common
if /usr/sbin/vapachectl --help >/tmp/unsafe-common.log 2>&1; then
    echo 'vapachectl sourced a writable privileged control library' >&2
    exit 1
fi
grep -q 'unsafe installed control library' /tmp/unsafe-common.log
chmod 0644 /usr/lib/vapache/control-common

# A pre-provisioned TLS vhost may name its future Certbot lineage before the
# first certificate exists. Keep that state fail-closed, but make the recovery
# command concrete instead of leaving the administrator in a bootstrap loop.
cat >/etc/apache2/sites-enabled/vapache-missing-cert.conf <<'EOF'
Listen 127.0.0.1:9443
<VirtualHost 127.0.0.1:9443>
ServerName example.test
SSLEngine On
SSLCertificateFile /etc/letsencrypt/live/example.test/fullchain.pem
SSLCertificateKeyFile /etc/letsencrypt/live/example.test/privkey.pem
</VirtualHost>
EOF
if /usr/sbin/vapachectl configtest >/tmp/missing-cert.log 2>&1; then
    echo 'Vapache accepted a nonexistent Certbot lineage' >&2
    exit 1
fi
grep -Fq 'sudo certbot certonly --standalone -d example.test' \
    /tmp/missing-cert.log || {
        cat /tmp/missing-cert.log >&2
        exit 1
    }
rm -f /etc/apache2/sites-enabled/vapache-missing-cert.conf

install -d -m 0700 \
    /etc/letsencrypt/archive/example.test \
    /etc/letsencrypt/live/example.test \
    /etc/letsencrypt/renewal
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj /CN=Vapache-Certbot-Test-CA \
    -keyout /tmp/ca.key -out /tmp/ca.pem >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=example.test \
    -keyout /etc/letsencrypt/archive/example.test/privkey1.pem \
    -out /tmp/leaf.csr >/dev/null 2>&1
openssl x509 -req -in /tmp/leaf.csr \
    -CA /tmp/ca.pem -CAkey /tmp/ca.key -CAcreateserial -days 1 \
    -out /etc/letsencrypt/archive/example.test/cert1.pem >/dev/null 2>&1
cp /tmp/ca.pem /etc/letsencrypt/archive/example.test/chain1.pem
cat /etc/letsencrypt/archive/example.test/cert1.pem /tmp/ca.pem \
    >/etc/letsencrypt/archive/example.test/fullchain1.pem
chmod 0600 /etc/letsencrypt/archive/example.test/privkey1.pem
for name in cert chain fullchain privkey; do
    ln -s "../../archive/example.test/${name}1.pem" \
        "/etc/letsencrypt/live/example.test/${name}.pem"
done
cat >/etc/letsencrypt/renewal/example.test.conf <<'EOF'
version = 4.0.0
archive_dir = /etc/letsencrypt/archive/example.test
cert = /etc/letsencrypt/live/example.test/cert.pem
privkey = /etc/letsencrypt/live/example.test/privkey.pem
chain = /etc/letsencrypt/live/example.test/chain.pem
fullchain = /etc/letsencrypt/live/example.test/fullchain.pem

[renewalparams]
account = integration-test
server = https://acme-staging-v02.api.letsencrypt.org/directory
authenticator = apache
installer = apache
key_type = rsa
EOF
chmod 0600 /etc/letsencrypt/renewal/example.test.conf

# Do not silently overwrite an administrator-provided control integration.
printf '%s\n' 'apache-ctl = /usr/local/sbin/custom-apachectl' \
    >/etc/letsencrypt/cli.ini
chmod 0600 /etc/letsencrypt/cli.ini
if /usr/sbin/vapache-switch --yes >/tmp/custom-control.log 2>&1; then
    echo 'vapache-switch unexpectedly replaced a custom Certbot control path' >&2
    exit 1
fi
grep -qx 'apache-ctl = /usr/local/sbin/custom-apachectl' \
    /etc/letsencrypt/cli.ini
rm -f /etc/letsencrypt/cli.ini

# Exercise the switch's persistent renewal migration and hook installation
# without starting an init system inside this test container.
install -d -m 0755 /tmp/switch-bin
cat >/tmp/switch-bin/systemctl <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>/tmp/vapache-switch-systemctl.calls
if [ -e /tmp/vapache-switch-interrupt ] \
    && [ "$1" = disable ] && [ "${3:-}" = apache2.service ]; then
    rm -f /tmp/vapache-switch-interrupt
    kill -TERM "$PPID"
    exit 1
fi
case "$1" in
    is-active|is-enabled)
        [ "${3:-}" = apache2.service ]
        ;;
    list-unit-files)
        [ "${2:-}" = apache2.service ] && echo 'apache2.service enabled'
        exit 0
        ;;
    daemon-reload|disable|enable|start|stop|restart) exit 0 ;;
    *) exit 0 ;;
esac
EOF
chmod 0755 /tmp/switch-bin/systemctl

# A signal in the service-transition window must restore Apache's exact prior
# enabled/active state and stop any partial Vapache start.
: >/tmp/vapache-switch-systemctl.calls
touch /tmp/vapache-switch-interrupt
if VAPACHE_SYSTEMCTL=/tmp/switch-bin/systemctl \
    /usr/sbin/vapache-switch --yes >/tmp/switch-interrupted.log 2>&1; then
    echo 'interrupted vapache-switch unexpectedly succeeded' >&2
    exit 1
fi
grep -qx 'disable --now apache2.service' /tmp/vapache-switch-systemctl.calls
grep -qx 'disable --now vapache.service' /tmp/vapache-switch-systemctl.calls
grep -qx 'enable apache2.service' /tmp/vapache-switch-systemctl.calls
grep -qx 'start apache2.service' /tmp/vapache-switch-systemctl.calls

: >/tmp/vapache-switch-systemctl.calls
VAPACHE_SYSTEMCTL=/tmp/switch-bin/systemctl /usr/sbin/vapache-switch --yes \
    >/tmp/switch.log 2>&1
grep -Eq '^apache_ctl[[:space:]]*=[[:space:]]*/usr/lib/vapache/certbot-apachectl$' \
    /etc/letsencrypt/renewal/example.test.conf
grep -Eq '^apache-ctl[[:space:]]*=[[:space:]]*/usr/lib/vapache/certbot-apachectl$' \
    /etc/letsencrypt/cli.ini
test "$(readlink /etc/letsencrypt/renewal-hooks/deploy/vapache-reload)" \
    = /usr/lib/vapache/certbot-deploy-hook

/usr/sbin/vapachectl foreground >/tmp/vapache.log 2>&1 &
initial_server_pid=$!
cleanup() {
    /usr/sbin/vapachectl stop >/dev/null 2>&1 || true
    kill "$initial_server_pid" >/dev/null 2>&1 || true
    wait "$initial_server_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ready=0
for attempt in $(seq 1 100); do
    if curl --noproxy '*' --max-time 2 --fail --silent \
        http://127.0.0.1/ >/dev/null; then
        ready=1
        break
    fi
    kill -0 "$initial_server_pid"
    sleep 0.1
done
test "$ready" -eq 1

# Model systemd's root-started replacement generation. The production shim
# selects this path so the first certificate can introduce a privileged :443
# listener; this container intentionally has no init system of its own.
cat >/tmp/systemctl <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>/tmp/vapache-systemctl.calls
case "$1" in
    is-active)
        exit 0
        ;;
    restart)
        old_pid=$(cat /run/apache2/apache2.pid)
        /usr/sbin/vapachectl stop >/dev/null 2>&1
        for attempt in $(seq 1 100); do
            if ! kill -0 "$old_pid" 2>/dev/null; then
                break
            fi
            sleep 0.05
        done
        nohup /usr/sbin/vapachectl foreground \
            >>/tmp/vapache.log 2>&1 </dev/null &
        for attempt in $(seq 1 100); do
            new_pid=$(cat /run/apache2/apache2.pid 2>/dev/null || true)
            if [ -n "$new_pid" ] && [ "$new_pid" != "$old_pid" ] \
                && kill -0 "$new_pid" 2>/dev/null; then
                exit 0
            fi
            sleep 0.05
        done
        exit 1
        ;;
    *) exit 1 ;;
esac
EOF
chmod 0755 /tmp/systemctl

# No --apache-ctl argument is needed: vapache-switch made ordinary
# `certbot --apache` invocations select the shim through Certbot's cli.ini.
VAPACHE_SYSTEMCTL=/tmp/systemctl \
    certbot install --cert-name example.test --apache \
        --non-interactive --no-redirect >/tmp/certbot.log 2>&1 || {
            cat /tmp/certbot.log >&2
            exit 1
        }
grep -qx 'restart vapache.service' /tmp/vapache-systemctl.calls
grep -q 'SSLCertificateFile /etc/letsencrypt/live/example.test/fullchain.pem' \
    /etc/apache2/sites-available/example.test-le-ssl.conf
grep -q 'Include /etc/letsencrypt/options-ssl-apache.conf' \
    /etc/apache2/sites-available/example.test-le-ssl.conf

ready=0
for attempt in $(seq 1 100); do
    if curl --noproxy '*' --max-time 2 --insecure --fail --silent \
        --resolve example.test:443:127.0.0.1 \
        https://example.test/ -o /tmp/served.html; then
        ready=1
        break
    fi
    sleep 0.1
done
if [[ "$ready" != 1 ]]; then
    cat /tmp/certbot.log >&2
    cat /tmp/vapache.log >&2
    cat /var/log/apache2/error.log >&2
    exit 1
fi
cmp /tmp/served.html /var/www/html/index.html

expected_fingerprint=$(openssl x509 \
    -in /etc/letsencrypt/archive/example.test/cert1.pem \
    -noout -fingerprint -sha256)
presented_fingerprint=$(printf '' \
    | openssl s_client -connect 127.0.0.1:443 \
        -servername example.test 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256)
test "$presented_fingerprint" = "$expected_fingerprint"

# Use the installed plugin's own HTTP-01 templates to verify the authenticator
# path as well as its installer path, without contacting an ACME service.
challenge_dir=/var/lib/letsencrypt/http_challenges
install -d -m 0755 "$challenge_dir"
challenge_token=VapacheCertbotToken_123-abc
printf '%s' 'integration-key-authorization' \
    >"$challenge_dir/$challenge_token"
chmod 0644 "$challenge_dir/$challenge_token"
python3 - "$challenge_dir" <<'PY'
import pathlib
import sys
from certbot_apache._internal import configurator  # load shared object types first
from certbot_apache._internal.http_01 import ApacheHttp01

directory = sys.argv[1]
pathlib.Path("/etc/apache2/le_http_01_challenge_pre.conf").write_text(
    ApacheHttp01.CONFIG_TEMPLATE24_PRE.format(directory)
)
pathlib.Path("/etc/apache2/le_http_01_challenge_post.conf").write_text(
    ApacheHttp01.CONFIG_TEMPLATE24_POST.format(directory)
)
PY
sed -i '2i Include /etc/apache2/le_http_01_challenge_pre.conf' \
    /etc/apache2/sites-available/example.test.conf
sed -i '/<\/VirtualHost>/i Include /etc/apache2/le_http_01_challenge_post.conf' \
    /etc/apache2/sites-available/example.test.conf
/usr/sbin/vapachectl configtest >/tmp/challenge-configtest.log 2>&1 || {
    cat /tmp/challenge-configtest.log >&2
    exit 1
}
/usr/sbin/vapachectl graceful >/tmp/challenge-reload.log 2>&1
challenge_ready=0
for attempt in $(seq 1 100); do
    if response=$(curl --noproxy '*' --max-time 2 --fail --silent \
        --resolve example.test:80:127.0.0.1 \
        "http://example.test/.well-known/acme-challenge/$challenge_token"); then
        if [[ "$response" == integration-key-authorization ]]; then
            challenge_ready=1
            break
        fi
    fi
    sleep 0.1
done
if [[ "$challenge_ready" != 1 ]]; then
    echo 'Certbot HTTP-01 challenge probe failed' >&2
    curl --noproxy '*' --max-time 2 --silent --show-error --include \
        --resolve example.test:80:127.0.0.1 \
        "http://example.test/.well-known/acme-challenge/$challenge_token" \
        >/tmp/challenge-response 2>/tmp/challenge-curl || true
    cat /tmp/challenge-curl >&2
    cat /tmp/challenge-response >&2
    grep -E 'reload|rewrite|challenge|error' /var/log/apache2/error.log >&2 \
        || tail -20 /var/log/apache2/error.log >&2
    exit 1
fi

# Package removal must not strand Certbot on a control command that was just
# removed. Unrelated settings and the Apache plugin selection remain intact.
dpkg --remove vapache >/tmp/vapache-remove.log 2>&1 || {
    cat /tmp/vapache-remove.log >&2
    exit 1
}
! grep -q 'apache-ctl[[:space:]]*=[[:space:]]*/usr/lib/vapache/certbot-apachectl' \
    /etc/letsencrypt/cli.ini
! grep -q 'apache_ctl[[:space:]]*=[[:space:]]*/usr/lib/vapache/certbot-apachectl' \
    /etc/letsencrypt/renewal/example.test.conf
grep -qx 'authenticator = apache' /etc/letsencrypt/renewal/example.test.conf
test ! -e /etc/letsencrypt/renewal-hooks/deploy/vapache-reload
test ! -L /etc/letsencrypt/renewal-hooks/deploy/vapache-reload

echo 'Certbot Apache installer integration: pass'
CONTAINER
