# Linux packages

The `httpd-rs` packages install:

- `/usr/sbin/httpd-rs` — the server;
- `/usr/sbin/httpd-rsctl` — an Apache-layout-aware control wrapper;
- `/usr/sbin/httpd-rs-switch` — an explicit, interactive service switch;
- `/usr/lib/httpd-rs/certbot-apachectl` — a Certbot Apache-plugin control shim;
- `/usr/lib/httpd-rs/certbot-deploy-hook` — a conditional httpd-rs reload hook;
- `/usr/lib/httpd-rs/certbot-cleanup` — the package-removal integration cleanup;
- `/usr/lib/httpd-rs/control-common` — shared privileged path/command validation;
- `/usr/lib/systemd/system/httpd-rs.service` — the systemd service unit; and
- documentation below `/usr/share/doc/httpd-rs`.

They intentionally do not install, replace, or edit Apache configuration.
`httpd-rsctl` uses `/etc/apache2/apache2.conf` on Debian-family systems or
`/etc/httpd/conf/httpd.conf` on RPM-family systems. Set both
`HTTPD_RS_CONFDIR` and `HTTPD_RS_CONFIG` to use another existing Apache layout.
Debian-family Apache layouts use symlinks such as `sites-enabled/*`, while
httpd-rs deliberately refuses to follow symlinks for privileged configuration
inputs. The wrapper therefore materializes the selected Apache tree into a
root-controlled runtime snapshot below `/run/httpd-rs`; it rejects writable,
non-root-owned, or out-of-tree source links when run as root. When that
configuration requests a default-off httpd-rs capability, the wrapper uses
`httpd-rs --audit-capabilities` to derive only the missing declarations and
writes them into the snapshot. The original Apache tree remains unchanged.
Set `HTTPD_RS_AUTO_CAPABILITIES=0` to require explicit declarations in the
source configuration. Snapshotting is automatically limited to Debian-style
enabled-config layouts; set `HTTPD_RS_SNAPSHOT_CONFIG=0` or `1` to override
that choice. On the stock `/etc/httpd` layout, the runtime overlay also
supplies RHEL's compiled-in `/run/httpd/httpd.pid` default, which is not
present as a directive in `httpd.conf`.

Installation does not enable or start httpd-rs and does not stop Apache. Run
`sudo httpd-rs-switch` when ready. The helper validates the configuration,
shows which Apache service it found, asks for confirmation, and only then
disables/stops Apache and enables/starts httpd-rs. If httpd-rs fails to start,
the helper restores Apache's previous active/enabled state.

The service retains systemd's namespace, privilege, kernel, and filesystem
hardening, but deliberately does not set `RestrictSUIDSGID=true`: systemd
implements that option by returning `ENOSYS` from `openat2`, which httpd-rs
requires for descriptor-contained configuration and content resolution. The
package workflow boots Debian 13 under systemd and serves a real request so
the unit's syscall policy is tested rather than merely syntax-checked.

When a Certbot installation or configuration exists, `httpd-rs-switch` installs
a deploy hook that reloads httpd-rs only while `httpd-rs.service` is active.
Renewal configurations using `authenticator = apache` or `installer = apache`
are updated to select `/usr/lib/httpd-rs/certbot-apachectl`. The same path is set
in Certbot's `cli.ini`, so new `certbot --apache` commands select it too. The shim
uses the real Apache control utility only for read-only version/module/include
discovery and Apache syntax validation, also requires httpd-rs's config test
while httpd-rs is active, and sends lifecycle commands to whichever daemon is
active. It does not replace an Apache-owned executable. Certbot-driven httpd-rs
lifecycle changes use a systemd restart because the first certificate can
introduce a new privileged port 443 listener; ordinary deploy-hook renewals
retain a graceful reload. For a new certificate, invoke Certbot with:

```sh
sudo certbot --apache -d example.com
```

That first-issuance path expects an HTTP-only virtual host; Certbot adds the
TLS virtual host after it has created the certificate. If an enabled TLS
virtual host already points at a nonexistent `/etc/letsencrypt/live/` lineage,
httpd-rs keeps the configuration invalid and prints the literal
`certbot certonly --standalone` command needed to create the lineage before
retrying `sudo httpd-rsctl configtest`. Port 80 must be free while the
standalone authenticator runs.

Without first running `httpd-rs-switch`, pass
`--apache-ctl /usr/lib/httpd-rs/certbot-apachectl` explicitly.
Package removal deletes only these exact httpd-rs settings and hook from
Certbot's configuration, so it does not leave a dangling control path.

The release binary targets `x86_64-unknown-linux-musl` and is a static PIE. It
therefore has no glibc version floor. httpd-rs still requires Linux 5.9 or newer
for its fail-closed `openat2` path-resolution and `close_range`
descriptor-isolation boundaries.

Release artifacts are reproducible. The workflow uses the pinned Rust
toolchain in a digest-pinned container, an exact-version Debian package set,
and the commit timestamp as `SOURCE_DATE_EPOCH`. It remaps checkout, target, and
tool-cache paths out of the executable and normalizes archive and package
ownership, timestamps, RPM build host, and RPM build time. The release run is
network-isolated after Cargo has verified every source against `Cargo.lock`.
The gate builds in two different source and target paths and requires
identical bytes for the loose executable, tarball, Debian package, RPM package,
and `SHA256SUMS` before anything is uploaded. Run the same gate locally with:

```sh
packaging/run-reproducible-build.sh --output release
```

GitHub also emits an artifact attestation for every file in the release set.
For a tagged build, verify a downloaded asset against GitHub's build
provenance with `gh attestation verify ASSET --repo JD-P/httpd-rs`, in addition
to checking `SHA256SUMS`.

All privileged helpers replace inherited command lookup with the fixed system
path, reject shell startup environments, validate executable overrides and the
complete ownership chain of every mutable path, and serialize snapshot/service
transitions below `/run/httpd-rs`. Configuration snapshots accept only regular
files and directories. An interrupted `httpd-rs-switch` disables a partial
httpd-rs start and restores Apache's exact previous active/enabled state.

The workflow also uploads the loose `httpd-rs` executable. GitHub's artifact
transport may clear its executable bit; run `chmod +x httpd-rs-*` after a loose
download, or use the tar, Debian, or RPM payload, which preserves file modes.
