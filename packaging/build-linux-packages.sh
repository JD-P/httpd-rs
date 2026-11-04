#!/bin/bash -p
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
unset CDPATH ENV BASH_ENV
umask 022

usage() {
    echo "Usage: $0 --binary PATH --version VERSION --output DIR" >&2
    exit 2
}

binary=
version=
output=
while (($#)); do
    case "$1" in
        --binary)
            (($# >= 2)) || usage
            binary=$2
            shift 2
            ;;
        --version)
            (($# >= 2)) || usage
            version=$2
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

[[ -n "$binary" && -n "$version" && -n "$output" ]] || usage
[[ -f "$binary" && -x "$binary" ]] || {
    echo "packaging: binary is not an executable file: $binary" >&2
    exit 1
}
[[ "$version" =~ ^[0-9][0-9A-Za-z.+~-]*$ ]] || {
    echo "packaging: unsupported version: $version" >&2
    exit 1
}

for command in dpkg-deb rpmbuild readelf sha256sum tar gzip; do
    command -v "$command" >/dev/null || {
        echo "packaging: missing required command: $command" >&2
        exit 1
    }
done

if readelf -d "$binary" 2>/dev/null | grep -q '(NEEDED)'; then
    echo "packaging: portable binary has dynamic dependencies" >&2
    exit 1
fi
readelf -h "$binary" | grep -q 'Machine:.*Advanced Micro Devices X86-64' || {
    echo "packaging: portable binary is not x86-64" >&2
    exit 1
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
output=$(mkdir -p -- "$output" && cd -- "$output" && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT

release=1
deb_name="vapache_${version}-${release}_amd64.deb"
rpm_version=${version//-/~}
rpm_name="vapache-${rpm_version}-${release}.x86_64.rpm"
raw_name="vapached-${version}-linux-x86_64-musl"
archive_name="vapache-${version}-linux-x86_64-musl.tar.gz"

install -m 0755 "$binary" "$output/$raw_name"

archive_root="$work_dir/vapache-${version}-linux-x86_64-musl"
install -Dm 0755 "$binary" "$archive_root/usr/sbin/vapached"
install -Dm 0755 "$script_dir/vapachectl" "$archive_root/usr/sbin/vapachectl"
install -Dm 0755 "$script_dir/vapache-switch" "$archive_root/usr/sbin/vapache-switch"
install -Dm 0755 "$script_dir/vapache-certbot-apachectl" \
    "$archive_root/usr/lib/vapache/certbot-apachectl"
install -Dm 0755 "$script_dir/vapache-certbot-deploy-hook" \
    "$archive_root/usr/lib/vapache/certbot-deploy-hook"
install -Dm 0755 "$script_dir/vapache-certbot-cleanup" \
    "$archive_root/usr/lib/vapache/certbot-cleanup"
install -Dm 0644 "$script_dir/vapache-control-common" \
    "$archive_root/usr/lib/vapache/control-common"
install -Dm 0644 "$script_dir/vapache.service" \
    "$archive_root/usr/lib/systemd/system/vapache.service"
install -Dm 0644 "$repo_root/README.md" "$archive_root/usr/share/doc/vapache/README.md"
install -Dm 0644 "$script_dir/README.md" \
    "$archive_root/usr/share/doc/vapache/PACKAGING.md"
install -Dm 0644 "$repo_root/LICENSE" "$archive_root/usr/share/licenses/vapache/LICENSE"

source_date_epoch=${SOURCE_DATE_EPOCH:-0}
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
    -C "$work_dir" -cf - "$(basename -- "$archive_root")" \
    | gzip -n >"$output/$archive_name"

deb_root="$work_dir/deb"
install -Dm 0755 "$binary" "$deb_root/usr/sbin/vapached"
install -Dm 0755 "$script_dir/vapachectl" "$deb_root/usr/sbin/vapachectl"
install -Dm 0755 "$script_dir/vapache-switch" "$deb_root/usr/sbin/vapache-switch"
install -Dm 0755 "$script_dir/vapache-certbot-apachectl" \
    "$deb_root/usr/lib/vapache/certbot-apachectl"
install -Dm 0755 "$script_dir/vapache-certbot-deploy-hook" \
    "$deb_root/usr/lib/vapache/certbot-deploy-hook"
install -Dm 0755 "$script_dir/vapache-certbot-cleanup" \
    "$deb_root/usr/lib/vapache/certbot-cleanup"
install -Dm 0644 "$script_dir/vapache-control-common" \
    "$deb_root/usr/lib/vapache/control-common"
install -Dm 0644 "$script_dir/vapache.service" \
    "$deb_root/usr/lib/systemd/system/vapache.service"
install -Dm 0644 "$repo_root/README.md" "$deb_root/usr/share/doc/vapache/README.md"
install -Dm 0644 "$script_dir/README.md" "$deb_root/usr/share/doc/vapache/PACKAGING.md"
install -Dm 0644 "$repo_root/LICENSE" "$deb_root/usr/share/doc/vapache/copyright"
install -d -m 0755 "$deb_root/DEBIAN"
cat >"$deb_root/DEBIAN/control" <<EOF
Package: vapache
Version: ${version}-${release}
Section: httpd
Priority: optional
Architecture: amd64
Maintainer: vapache project <noreply@github.com>
Homepage: https://github.com/JD-P/vapache
Suggests: apache2
Description: Apache-compatible web server with a security-focused core
 Vapache reads an existing Apache configuration and serves it through the
 vapached daemon. This package leaves Apache configuration and service state
 untouched until the administrator explicitly runs vapache-switch.
EOF
cat >"$deb_root/DEBIAN/postinst" <<'EOF'
#!/bin/sh -p
set -e
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV
umask 022
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ -r /etc/apache2/apache2.conf ]; then
    echo "vapache: existing /etc/apache2 configuration preserved"
    echo "vapache: Apache service state is unchanged; 'sudo vapache-switch' will ask before replacing it"
else
    echo "vapache: no /etc/apache2/apache2.conf found; configure VAPACHE_CONFDIR and VAPACHE_CONFIG before starting"
fi
exit 0
EOF
cat >"$deb_root/DEBIAN/prerm" <<'EOF'
#!/bin/sh -p
set -e
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV
umask 022
if [ "${1:-}" = remove ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now vapache.service >/dev/null 2>&1 || true
fi
if [ "${1:-}" = remove ] && [ -x /usr/lib/vapache/certbot-cleanup ]; then
    /usr/lib/vapache/certbot-cleanup || \
        echo "vapache: warning: could not clean Certbot integration" >&2
fi
exit 0
EOF
cat >"$deb_root/DEBIAN/postrm" <<'EOF'
#!/bin/sh -p
set -e
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV
umask 022
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 0755 "$deb_root/DEBIAN/postinst" "$deb_root/DEBIAN/prerm" "$deb_root/DEBIAN/postrm"
dpkg-deb --root-owner-group -Zxz -z9 --build "$deb_root" "$output/$deb_name"

rpm_top="$work_dir/rpm"
mkdir -p "$rpm_top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
install -m 0755 "$binary" "$rpm_top/SOURCES/vapached"
install -m 0755 "$script_dir/vapachectl" "$rpm_top/SOURCES/vapachectl"
install -m 0755 "$script_dir/vapache-switch" "$rpm_top/SOURCES/vapache-switch"
install -m 0755 "$script_dir/vapache-certbot-apachectl" \
    "$rpm_top/SOURCES/vapache-certbot-apachectl"
install -m 0755 "$script_dir/vapache-certbot-deploy-hook" \
    "$rpm_top/SOURCES/vapache-certbot-deploy-hook"
install -m 0755 "$script_dir/vapache-certbot-cleanup" \
    "$rpm_top/SOURCES/vapache-certbot-cleanup"
install -m 0644 "$script_dir/vapache-control-common" \
    "$rpm_top/SOURCES/vapache-control-common"
install -m 0644 "$script_dir/vapache.service" "$rpm_top/SOURCES/vapache.service"
install -m 0644 "$repo_root/README.md" "$rpm_top/SOURCES/README.md"
install -m 0644 "$script_dir/README.md" "$rpm_top/SOURCES/PACKAGING.md"
install -m 0644 "$repo_root/LICENSE" "$rpm_top/SOURCES/LICENSE"
cat >"$rpm_top/SPECS/vapache.spec" <<EOF
Name:           vapache
Version:        ${rpm_version}
Release:        ${release}
Summary:        Apache-compatible web server with a security-focused core
License:        Apache-2.0
URL:            https://github.com/JD-P/vapache
Source0:        vapached
Source1:        vapachectl
Source2:        vapache-switch
Source3:        vapache-certbot-apachectl
Source4:        vapache-certbot-deploy-hook
Source5:        vapache-certbot-cleanup
Source6:        vapache-control-common
Source7:        vapache.service
Source8:        README.md
Source9:        PACKAGING.md
Source10:       LICENSE
BuildArch:      x86_64
AutoReqProv:    no
Suggests:       httpd
%global __os_install_post %{nil}

%description
Vapache reads an existing Apache configuration and serves it through the
vapached daemon. The package leaves Apache configuration and service state
untouched until the administrator explicitly runs vapache-switch.

%prep

%build

%install
install -Dm 0755 %{SOURCE0} %{buildroot}/usr/sbin/vapached
install -Dm 0755 %{SOURCE1} %{buildroot}/usr/sbin/vapachectl
install -Dm 0755 %{SOURCE2} %{buildroot}/usr/sbin/vapache-switch
install -Dm 0755 %{SOURCE3} %{buildroot}/usr/lib/vapache/certbot-apachectl
install -Dm 0755 %{SOURCE4} %{buildroot}/usr/lib/vapache/certbot-deploy-hook
install -Dm 0755 %{SOURCE5} %{buildroot}/usr/lib/vapache/certbot-cleanup
install -Dm 0644 %{SOURCE6} %{buildroot}/usr/lib/vapache/control-common
install -Dm 0644 %{SOURCE7} %{buildroot}/usr/lib/systemd/system/vapache.service
install -Dm 0644 %{SOURCE8} %{buildroot}/usr/share/doc/vapache/README.md
install -Dm 0644 %{SOURCE9} %{buildroot}/usr/share/doc/vapache/PACKAGING.md
install -Dm 0644 %{SOURCE10} %{buildroot}/usr/share/licenses/vapache/LICENSE

%post
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV
umask 022
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi
if [ -r /etc/httpd/conf/httpd.conf ]; then
    echo "vapache: existing /etc/httpd configuration preserved"
    echo "vapache: Apache service state is unchanged; 'sudo vapache-switch' will ask before replacing it"
else
    echo "vapache: no /etc/httpd/conf/httpd.conf found; configure VAPACHE_CONFDIR and VAPACHE_CONFIG before starting"
fi

%preun
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV
umask 022
if [ \$1 -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now vapache.service >/dev/null 2>&1 || :
fi
if [ \$1 -eq 0 ] && [ -x /usr/lib/vapache/certbot-cleanup ]; then
    /usr/lib/vapache/certbot-cleanup || \
        echo "vapache: warning: could not clean Certbot integration" >&2
fi

%postun
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV
umask 022
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

%files
%attr(0755,root,root) /usr/sbin/vapached
%attr(0755,root,root) /usr/sbin/vapachectl
%attr(0755,root,root) /usr/sbin/vapache-switch
%attr(0755,root,root) /usr/lib/vapache/certbot-apachectl
%attr(0755,root,root) /usr/lib/vapache/certbot-deploy-hook
%attr(0755,root,root) /usr/lib/vapache/certbot-cleanup
%attr(0644,root,root) /usr/lib/vapache/control-common
%attr(0644,root,root) /usr/lib/systemd/system/vapache.service
%doc /usr/share/doc/vapache/README.md
%doc /usr/share/doc/vapache/PACKAGING.md
%license /usr/share/licenses/vapache/LICENSE
EOF
rpmbuild --define "_topdir $rpm_top" --define "_build_id_links none" \
    -bb "$rpm_top/SPECS/vapache.spec"
rpm_path=$(find "$rpm_top/RPMS" -type f -name '*.rpm' -print -quit)
[[ -n "$rpm_path" ]] || {
    echo "packaging: rpmbuild did not produce an RPM" >&2
    exit 1
}
install -m 0644 "$rpm_path" "$output/$rpm_name"

(
    cd -- "$output"
    sha256sum "$raw_name" "$archive_name" "$deb_name" "$rpm_name" >SHA256SUMS
)

printf 'packaging: wrote artifacts to %s\n' "$output"
