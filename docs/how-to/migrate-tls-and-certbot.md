---
doc_type: how-to
audience: apache-operator
status: draft
contracts: DOC-HOWTO-TLS-001
---

# Migrate TLS and Certbot

Use this procedure to retain an existing Certbot lineage or to issue a new
certificate after you switch from Apache to Vapache. Contract
`DOC-HOWTO-TLS-001` binds this guide to the packaged Certbot tests.

## Prerequisites

Install the Vapache package. Keep the Apache configuration and
`/etc/letsencrypt` unchanged. Complete the
[configuration assessment](assess-apache-configuration.md) before you switch
services.

## 1. Record the certificate state

Run:

```console
$ sudo certbot certificates
$ sudo apache2ctl -t -D DUMP_VHOSTS
$ sudo apache2ctl configtest
Syntax OK
```

Record each certificate name, domain name, and TLS virtual host. Do not copy
files out of `/etc/letsencrypt/live`. Certbot maintains those paths.

## 2. Test the Vapache configuration

Run:

```console
$ sudo vapachectl configtest
Syntax OK
```

Vapache accepts an existing Certbot lineage when the final certificate and key
links resolve through a root-controlled tree. Correct an ownership or
writability error before you continue.

## 3. Switch the service

Run the packaged switch from a local administrative session:

```console
$ sudo vapache-switch
```

Review the reported Apache service, Certbot renewal configurations, and
planned changes. The switch installs a Certbot Apache-control shim and a
conditional deploy hook. The shim controls Vapache while `vapache.service` is
active. It controls Apache while Vapache is inactive.

If Vapache does not start, the switch restores the previous active and enabled
Apache state. See [Roll back to Apache](roll-back-to-apache.md) for a later
manual rollback.

## 4. Verify an existing lineage

Run a dry renewal and inspect the served certificate:

```console
$ sudo certbot renew --dry-run
$ openssl s_client -connect www.example.test:443 \
    -servername www.example.test </dev/null
```

Confirm the certificate subject, issuer, domain names, and expiry. Confirm that
the HTTP challenge path is reachable if the lineage uses HTTP-01.

## 5. Issue a new certificate

Create and enable an HTTP-only virtual host for the domain. Then run:

```console
$ sudo certbot --apache -d www.example.test
```

The Vapache shim lets the Apache plugin test configuration and reload the
active server. It does not permit Certbot to start Apache while Vapache owns
the listener.

If the configuration already names a lineage that does not exist, the
configuration test prints a `certbot certonly --standalone` command. Stop the
service that owns port 80, run the printed command, and start the service
again. Re-run `vapachectl configtest` before you enable the TLS virtual host.

## 6. Verify renewal control

Run:

```console
$ sudo systemctl status vapache.service
$ sudo certbot renew --dry-run
$ sudo journalctl -u vapache.service --since today
```

Confirm that Vapache remains active after the dry run. The deploy hook reloads
Vapache only after a successful renewal and only while the Vapache service is
active.

## Evidence

The [Certbot Apache integration test](../../tests/certbot_apache_integration.sh)
checks service selection, renewal edits, interruption recovery, and service
restoration. The [Certbot shim test](../../tests/certbot_apache_shim.sh) checks
the permitted Apache-plugin control commands. The
[packaging workflow](../../.github/workflows/artifacts.yml) runs these tests in
the package boundary.
