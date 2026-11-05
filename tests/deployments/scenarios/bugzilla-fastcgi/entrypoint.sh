#!/bin/sh
set -eu

: "${BUGZILLA_ROOT:?}"
: "${BZ_URLBASE:?}"
: "${VAPACHE_SOCKET_GID:?}"
cd "$BUGZILLA_ROOT"

while ! nc -z database 3306; do
  sleep 1
done

answers=/tmp/checksetup_answers.txt
sed \
  -e "s|%%BZ_URLBASE%%|$BZ_URLBASE|g" \
  /opt/vapache/checksetup_answers.txt >"$answers"
perl checksetup.pl "$answers"
# A fresh Bugzilla checkout can add newly introduced localconfig variables and
# deliberately stop after writing them.  The documented second pass consumes
# that completed file and performs the database/application setup.  Repeating
# checksetup is also harmless when the first pass completed the setup.
perl checksetup.pl "$answers"

# Freeze executable application code after setup. Only Bugzilla's generated
# data and extension state remain writable by the unprivileged FastCGI user.
chown -R root:root "$BUGZILLA_ROOT"
find "$BUGZILLA_ROOT" -type d -exec chmod 0755 {} +
find "$BUGZILLA_ROOT" -type f -exec chmod 0644 {} +
find "$BUGZILLA_ROOT" -type f \( -name '*.cgi' -o -name '*.pl' \) -exec chmod 0755 {} +
chown -R www-data:www-data "$BUGZILLA_ROOT/data"
chmod 0640 "$BUGZILLA_ROOT/localconfig"
chown root:www-data "$BUGZILLA_ROOT/localconfig"

rm -f /run/bugzilla/fcgi.sock
exec spawn-fcgi -n -s /run/bugzilla/fcgi.sock -M 0660 \
  -U www-data -G "$VAPACHE_SOCKET_GID" -u www-data -g www-data -- /usr/sbin/fcgiwrap -f
