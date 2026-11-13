#!/bin/bash -p
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
TZ=UTC
export LC_ALL TZ
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

source_date_epoch=${SOURCE_DATE_EPOCH:-0}
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || {
    echo "packaging: SOURCE_DATE_EPOCH must be a non-negative integer" >&2
    exit 1
}
export SOURCE_DATE_EPOCH="$source_date_epoch"

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
deb_name="httpd-rs_${version}-${release}_amd64.deb"
rpm_version=${version//-/~}
rpm_name="httpd-rs-${rpm_version}-${release}.x86_64.rpm"
raw_name="httpd-rs-${version}-linux-x86_64-musl"
archive_name="httpd-rs-${version}-linux-x86_64-musl.tar.gz"

install -m 0755 "$binary" "$output/$raw_name"

archive_root="$work_dir/httpd-rs-${version}-linux-x86_64-musl"
install -Dm 0755 "$binary" "$archive_root/usr/sbin/httpd-rs"
install -Dm 0755 "$script_dir/httpd-rsctl" "$archive_root/usr/sbin/httpd-rsctl"
install -Dm 0755 "$script_dir/httpd-rs-switch" "$archive_root/usr/sbin/httpd-rs-switch"
install -Dm 0755 "$script_dir/httpd-rs-certbot-apachectl" \
    "$archive_root/usr/lib/httpd-rs/certbot-apachectl"
install -Dm 0755 "$script_dir/httpd-rs-certbot-deploy-hook" \
    "$archive_root/usr/lib/httpd-rs/certbot-deploy-hook"
install -Dm 0755 "$script_dir/httpd-rs-certbot-cleanup" \
    "$archive_root/usr/lib/httpd-rs/certbot-cleanup"
install -Dm 0644 "$script_dir/httpd-rs-control-common" \
    "$archive_root/usr/lib/httpd-rs/control-common"
install -Dm 0644 "$script_dir/httpd-rs.service" \
    "$archive_root/usr/lib/systemd/system/httpd-rs.service"
install -Dm 0644 "$repo_root/README.md" "$archive_root/usr/share/doc/httpd-rs/README.md"
install -Dm 0644 "$script_dir/README.md" \
    "$archive_root/usr/share/doc/httpd-rs/PACKAGING.md"
install -Dm 0644 "$repo_root/LICENSE" "$archive_root/usr/share/licenses/httpd-rs/LICENSE"

tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
    -C "$work_dir" -cf - "$(basename -- "$archive_root")" \
    | gzip -n >"$output/$archive_name"

deb_root="$work_dir/deb"
install -Dm 0755 "$binary" "$deb_root/usr/sbin/httpd-rs"
install -Dm 0755 "$script_dir/httpd-rsctl" "$deb_root/usr/sbin/httpd-rsctl"
install -Dm 0755 "$script_dir/httpd-rs-switch" "$deb_root/usr/sbin/httpd-rs-switch"
install -Dm 0755 "$script_dir/httpd-rs-certbot-apachectl" \
    "$deb_root/usr/lib/httpd-rs/certbot-apachectl"
install -Dm 0755 "$script_dir/httpd-rs-certbot-deploy-hook" \
    "$deb_root/usr/lib/httpd-rs/certbot-deploy-hook"
install -Dm 0755 "$script_dir/httpd-rs-certbot-cleanup" \
    "$deb_root/usr/lib/httpd-rs/certbot-cleanup"
install -Dm 0644 "$script_dir/httpd-rs-control-common" \
    "$deb_root/usr/lib/httpd-rs/control-common"
install -Dm 0644 "$script_dir/httpd-rs.service" \
    "$deb_root/usr/lib/systemd/system/httpd-rs.service"
install -Dm 0644 "$repo_root/README.md" "$deb_root/usr/share/doc/httpd-rs/README.md"
install -Dm 0644 "$script_dir/README.md" "$deb_root/usr/share/doc/httpd-rs/PACKAGING.md"
install -Dm 0644 "$repo_root/LICENSE" "$deb_root/usr/share/doc/httpd-rs/copyright"
install -d -m 0755 "$deb_root/DEBIAN"
cat >"$deb_root/DEBIAN/control" <<EOF
Package: httpd-rs
Version: ${version}-${release}
Section: httpd
Priority: optional
Architecture: amd64
Maintainer: httpd-rs project <noreply@github.com>
Homepage: https://github.com/JD-P/httpd-rs
Suggests: apache2
Description: Apache-compatible web server with a security-focused core
 httpd-rs reads an existing Apache configuration and serves it through the
 httpd-rs daemon. This package leaves Apache configuration and service state
 untouched until the administrator explicitly runs httpd-rs-switch.
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
    echo "httpd-rs: existing /etc/apache2 configuration preserved"
    echo "httpd-rs: Apache service state is unchanged; 'sudo httpd-rs-switch' will ask before replacing it"
else
    echo "httpd-rs: no /etc/apache2/apache2.conf found; configure HTTPD_RS_CONFDIR and HTTPD_RS_CONFIG before starting"
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
    systemctl disable --now httpd-rs.service >/dev/null 2>&1 || true
fi
if [ "${1:-}" = remove ] && [ -x /usr/lib/httpd-rs/certbot-cleanup ]; then
    /usr/lib/httpd-rs/certbot-cleanup || \
        echo "httpd-rs: warning: could not clean Certbot integration" >&2
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
# dpkg-deb uses the staged mtimes for data.tar. Normalize leaves first and
# directories last so touching a child cannot perturb its parent's mtime.
find "$deb_root" -depth -exec touch -h -d "@$source_date_epoch" -- {} +
dpkg-deb --root-owner-group -Zxz -z9 --build "$deb_root" "$output/$deb_name"

rpm_top="$work_dir/rpm"
mkdir -p "$rpm_top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
install -m 0755 "$binary" "$rpm_top/SOURCES/httpd-rs"
install -m 0755 "$script_dir/httpd-rsctl" "$rpm_top/SOURCES/httpd-rsctl"
install -m 0755 "$script_dir/httpd-rs-switch" "$rpm_top/SOURCES/httpd-rs-switch"
install -m 0755 "$script_dir/httpd-rs-certbot-apachectl" \
    "$rpm_top/SOURCES/httpd-rs-certbot-apachectl"
install -m 0755 "$script_dir/httpd-rs-certbot-deploy-hook" \
    "$rpm_top/SOURCES/httpd-rs-certbot-deploy-hook"
install -m 0755 "$script_dir/httpd-rs-certbot-cleanup" \
    "$rpm_top/SOURCES/httpd-rs-certbot-cleanup"
install -m 0644 "$script_dir/httpd-rs-control-common" \
    "$rpm_top/SOURCES/httpd-rs-control-common"
install -m 0644 "$script_dir/httpd-rs.service" "$rpm_top/SOURCES/httpd-rs.service"
install -m 0644 "$repo_root/README.md" "$rpm_top/SOURCES/README.md"
install -m 0644 "$script_dir/README.md" "$rpm_top/SOURCES/PACKAGING.md"
install -m 0644 "$repo_root/LICENSE" "$rpm_top/SOURCES/LICENSE"
cat >"$rpm_top/SPECS/httpd-rs.spec" <<EOF
Name:           httpd-rs
Version:        ${rpm_version}
Release:        ${release}
Summary:        Apache-compatible web server with a security-focused core
License:        Apache-2.0
URL:            https://github.com/JD-P/httpd-rs
Source0:        httpd-rs
Source1:        httpd-rsctl
Source2:        httpd-rs-switch
Source3:        httpd-rs-certbot-apachectl
Source4:        httpd-rs-certbot-deploy-hook
Source5:        httpd-rs-certbot-cleanup
Source6:        httpd-rs-control-common
Source7:        httpd-rs.service
Source8:        README.md
Source9:        PACKAGING.md
Source10:       LICENSE
BuildArch:      x86_64
AutoReqProv:    no
Suggests:       httpd
%global __os_install_post %{nil}

%description
httpd-rs reads an existing Apache configuration and serves it through the
httpd-rs daemon. The package leaves Apache configuration and service state
untouched until the administrator explicitly runs httpd-rs-switch.

%prep

%build

%install
install -Dm 0755 %{SOURCE0} %{buildroot}/usr/sbin/httpd-rs
install -Dm 0755 %{SOURCE1} %{buildroot}/usr/sbin/httpd-rsctl
install -Dm 0755 %{SOURCE2} %{buildroot}/usr/sbin/httpd-rs-switch
install -Dm 0755 %{SOURCE3} %{buildroot}/usr/lib/httpd-rs/certbot-apachectl
install -Dm 0755 %{SOURCE4} %{buildroot}/usr/lib/httpd-rs/certbot-deploy-hook
install -Dm 0755 %{SOURCE5} %{buildroot}/usr/lib/httpd-rs/certbot-cleanup
install -Dm 0644 %{SOURCE6} %{buildroot}/usr/lib/httpd-rs/control-common
install -Dm 0644 %{SOURCE7} %{buildroot}/usr/lib/systemd/system/httpd-rs.service
install -Dm 0644 %{SOURCE8} %{buildroot}/usr/share/doc/httpd-rs/README.md
install -Dm 0644 %{SOURCE9} %{buildroot}/usr/share/doc/httpd-rs/PACKAGING.md
install -Dm 0644 %{SOURCE10} %{buildroot}/usr/share/licenses/httpd-rs/LICENSE
find %{buildroot} -depth -exec touch -h -d '@${source_date_epoch}' -- {} +

%post
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV
umask 022
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi
if [ -r /etc/httpd/conf/httpd.conf ]; then
    echo "httpd-rs: existing /etc/httpd configuration preserved"
    echo "httpd-rs: Apache service state is unchanged; 'sudo httpd-rs-switch' will ask before replacing it"
else
    echo "httpd-rs: no /etc/httpd/conf/httpd.conf found; configure HTTPD_RS_CONFDIR and HTTPD_RS_CONFIG before starting"
fi

%preun
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV
umask 022
if [ \$1 -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now httpd-rs.service >/dev/null 2>&1 || :
fi
if [ \$1 -eq 0 ] && [ -x /usr/lib/httpd-rs/certbot-cleanup ]; then
    /usr/lib/httpd-rs/certbot-cleanup || \
        echo "httpd-rs: warning: could not clean Certbot integration" >&2
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
%attr(0755,root,root) /usr/sbin/httpd-rs
%attr(0755,root,root) /usr/sbin/httpd-rsctl
%attr(0755,root,root) /usr/sbin/httpd-rs-switch
%attr(0755,root,root) /usr/lib/httpd-rs/certbot-apachectl
%attr(0755,root,root) /usr/lib/httpd-rs/certbot-deploy-hook
%attr(0755,root,root) /usr/lib/httpd-rs/certbot-cleanup
%attr(0644,root,root) /usr/lib/httpd-rs/control-common
%attr(0644,root,root) /usr/lib/systemd/system/httpd-rs.service
%doc /usr/share/doc/httpd-rs/README.md
%doc /usr/share/doc/httpd-rs/PACKAGING.md
%license /usr/share/licenses/httpd-rs/LICENSE
EOF
find "$rpm_top/SOURCES" "$rpm_top/SPECS" -depth \
    -exec touch -h -d "@$source_date_epoch" -- {} +
rpmbuild --define "_topdir $rpm_top" \
    --define "_build_id_links none" \
    --define "_buildhost reproducible.invalid" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    -bb "$rpm_top/SPECS/httpd-rs.spec"
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
