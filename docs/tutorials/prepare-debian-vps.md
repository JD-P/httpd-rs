---
doc_type: tutorial
audience: application-operator
status: draft
---

# Prepare a Debian VPS for a httpd-rs tutorial

This tutorial prepares a fresh Debian 13 VPS for the application tutorials.
It installs httpd-rs, removes Debian's example site, and configures Certbot to
control httpd-rs during certificate issuance and renewal.

## What you will do

You will install the Debian configuration layout, install httpd-rs, disable
Apache's example site, switch the active service to httpd-rs, and verify the
empty configuration.

## Before you start

Create an `amd64` Debian 13 VPS with Linux 5.9 or newer. You need a user with
`sudo` access. Download the current httpd-rs Debian package and its
`SHA256SUMS` file from the same [release
page](https://github.com/JD-P/httpd-rs/releases) to `/tmp`.

## 1. Check the host

```console
$ dpkg --print-architecture
amd64
$ uname -r
```

Do not continue if the architecture is not `amd64`. The kernel version must be
5.9 or newer.

## 2. Install the configuration layout and httpd-rs

```console
$ cd /tmp
$ grep ' httpd-rs_.*_amd64\.deb$' SHA256SUMS | sha256sum --check --strict
$ sudo apt update
$ sudo apt install apache2 ca-certificates certbot curl gnupg \
    python3-certbot-apache
$ sudo apt install /tmp/httpd-rs_*_amd64.deb
$ sudo a2dissite 000-default.conf
$ sudo httpd-rsctl configtest
$ sudo httpd-rs-switch --yes
```

Do not install the package if the checksum command does not report `OK`. Keep
only one httpd-rs Debian package in `/tmp` so that the install command selects
the package that you verified.

The Apache package supplies `/etc/apache2` and its configuration utilities.
httpd-rs reads that configuration. `httpd-rs-switch` stops and disables Apache,
starts httpd-rs, installs the Certbot control shim, and installs the renewal
reload hook. It also restores Apache if httpd-rs does not start.

## 3. Test the empty configuration and service state

```console
$ sudo httpd-rsctl configtest
$ systemctl is-enabled apache2.service
disabled
$ systemctl is-active apache2.service
inactive
$ systemctl is-enabled httpd-rs.service
enabled
$ systemctl is-active httpd-rs.service
active
```

Continue with one application tutorial. It will first add an HTTP-only virtual
host, use Certbot's Apache authenticator to obtain a certificate through the
httpd-rs control shim, and then replace that temporary host with explicit HTTP
redirection and HTTPS configuration.
