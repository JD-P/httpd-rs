---
doc_type: tutorial
audience: application-operator
status: draft
---

# Prepare a Debian VPS for a Vapache tutorial

This tutorial prepares a fresh Debian 13 VPS for the application tutorials.
It installs Vapache without starting Apache or Vapache.

## What you will do

You will install the Debian configuration layout, install Vapache, stop Apache,
and verify that Vapache can read the empty Debian configuration.

## Before you start

Create an `amd64` Debian 13 VPS with Linux 5.9 or newer. You need a user with
`sudo` access. Download the current Vapache Debian package from the [release
page](https://github.com/JD-P/vapache/releases) to `/tmp/vapache.deb`.

## 1. Check the host

```console
$ dpkg --print-architecture
amd64
$ uname -r
```

Do not continue if the architecture is not `amd64`. The kernel version must be
5.9 or newer.

## 2. Install the configuration layout and Vapache

```console
$ sudo apt update
$ sudo apt install apache2 ca-certificates certbot curl
$ sudo apt install /tmp/vapache.deb
$ sudo systemctl disable --now apache2.service
```

The Apache package supplies `/etc/apache2` and its configuration utilities.
Vapache reads that configuration. Apache does not need to run.

## 3. Test the empty configuration

```console
$ sudo vapachectl configtest
$ systemctl is-enabled apache2.service
disabled
$ systemctl is-active apache2.service
inactive
```

Do not start Vapache yet. Continue with one application tutorial, add its
virtual host, and start Vapache when that tutorial tells you to do so.
