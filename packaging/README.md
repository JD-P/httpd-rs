# Linux packages

The `vapache` packages install:

- `/usr/sbin/vapached` — the server;
- `/usr/sbin/vapachectl` — an Apache-layout-aware control wrapper;
- `/usr/sbin/vapache-switch` — an explicit, interactive service switch;
- `/usr/lib/vapache/certbot-apachectl` — a Certbot Apache-plugin control shim;
- `/usr/lib/vapache/certbot-deploy-hook` — a conditional Vapache reload hook;
- `/usr/lib/vapache/certbot-cleanup` — the package-removal integration cleanup;
- `/usr/lib/vapache/control-common` — shared privileged path/command validation;
- `/usr/lib/systemd/system/vapache.service` — the systemd service unit; and
- documentation below `/usr/share/doc/vapache`.

They intentionally do not install, replace, or edit Apache configuration.
`vapachectl` uses `/etc/apache2/apache2.conf` on Debian-family systems or
`/etc/httpd/conf/httpd.conf` on RPM-family systems. Set both
`VAPACHE_CONFDIR` and `VAPACHE_CONFIG` to use another existing Apache layout.
Debian-family Apache layouts use symlinks such as `sites-enabled/*`, while
vapache deliberately refuses to follow symlinks for privileged configuration
inputs. The wrapper therefore materializes the selected Apache tree into a
root-controlled runtime snapshot below `/run/vapache`; it rejects writable,
non-root-owned, or out-of-tree source links when run as root. When that
configuration requests a default-off vapache capability, the wrapper uses
`vapached --audit-capabilities` to derive only the missing declarations and
writes them into the snapshot. The original Apache tree remains unchanged.
Set `VAPACHE_AUTO_CAPABILITIES=0` to require explicit declarations in the
source configuration. Snapshotting is automatically limited to Debian-style
enabled-config layouts; set `VAPACHE_SNAPSHOT_CONFIG=0` or `1` to override
that choice. On the stock `/etc/httpd` layout, the runtime overlay also
supplies RHEL's compiled-in `/run/httpd/httpd.pid` default, which is not
present as a directive in `httpd.conf`.

Installation does not enable or start vapache and does not stop Apache. Run
`sudo vapache-switch` when ready. The helper validates the configuration,
shows which Apache service it found, asks for confirmation, and only then
disables/stops Apache and enables/starts vapache. If vapache fails to start,
the helper restores Apache's previous active/enabled state.

The service retains systemd's namespace, privilege, kernel, and filesystem
hardening, but deliberately does not set `RestrictSUIDSGID=true`: systemd
implements that option by returning `ENOSYS` from `openat2`, which Vapache
requires for descriptor-contained configuration and content resolution. The
package workflow boots Debian 13 under systemd and serves a real request so
the unit's syscall policy is tested rather than merely syntax-checked.

When a Certbot installation or configuration exists, `vapache-switch` installs
a deploy hook that reloads Vapache only while `vapache.service` is active.
Renewal configurations using `authenticator = apache` or `installer = apache`
are updated to select `/usr/lib/vapache/certbot-apachectl`. The same path is set
in Certbot's `cli.ini`, so new `certbot --apache` commands select it too. The shim
uses the real Apache control utility only for read-only version/module/include
discovery and Apache syntax validation, also requires Vapache's config test
while Vapache is active, and sends lifecycle commands to whichever daemon is
active. It does not replace an Apache-owned executable. Certbot-driven Vapache
lifecycle changes use a systemd restart because the first certificate can
introduce a new privileged port 443 listener; ordinary deploy-hook renewals
retain a graceful reload. For a new certificate, invoke Certbot with:

```sh
sudo certbot --apache -d example.com
```

That first-issuance path expects an HTTP-only virtual host; Certbot adds the
TLS virtual host after it has created the certificate. If an enabled TLS
virtual host already points at a nonexistent `/etc/letsencrypt/live/` lineage,
Vapache keeps the configuration invalid and prints the literal
`certbot certonly --standalone` command needed to create the lineage before
retrying `sudo vapachectl configtest`. Port 80 must be free while the
standalone authenticator runs.

Without first running `vapache-switch`, pass
`--apache-ctl /usr/lib/vapache/certbot-apachectl` explicitly.
Package removal deletes only these exact Vapache settings and hook from
Certbot's configuration, so it does not leave a dangling control path.

The release binary targets `x86_64-unknown-linux-musl` and is a static PIE. It
therefore has no glibc version floor. Vapache still requires Linux 5.9 or newer
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
provenance with `gh attestation verify ASSET --repo JD-P/vapache`, in addition
to checking `SHA256SUMS`.

All privileged helpers replace inherited command lookup with the fixed system
path, reject shell startup environments, validate executable overrides and the
complete ownership chain of every mutable path, and serialize snapshot/service
transitions below `/run/vapache`. Configuration snapshots accept only regular
files and directories. An interrupted `vapache-switch` disables a partial
Vapache start and restores Apache's exact previous active/enabled state.

The workflow also uploads the loose `vapached` executable. GitHub's artifact
transport may clear its executable bit; run `chmod +x vapached-*` after a loose
download, or use the tar, Debian, or RPM payload, which preserves file modes.
