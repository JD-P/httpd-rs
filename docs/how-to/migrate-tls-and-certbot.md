---
doc_type: how-to
audience: apache-operator
status: draft
contracts: DOC-HOWTO-TLS-001
---

# Migrate TLS and Certbot

httpd-rs can use certificates that Certbot already manages. The service switch
also configures Certbot to reload httpd-rs after a successful renewal. You do not
need to request replacement certificates only because you switch web servers.

This guide has separate instructions for an existing certificate and a new
certificate.

## Prerequisites

Install the httpd-rs package and complete the [configuration
assessment](assess-apache-configuration.md). Keep the current Apache service
available for rollback.

For an existing certificate, Certbot and `/etc/letsencrypt` must remain on the
host. To issue a new certificate with `certbot --apache`, install Certbot and
its Apache plugin.

## 1. Can httpd-rs use the existing certificates?

List the certificates that Certbot currently manages:

```console
$ sudo certbot certificates
```

Save this output. You will use it after the switch to confirm that the
certificate names and domain names did not change.

Confirm that Apache accepts its current configuration. On a Debian-family
system, run:

```console
$ sudo apache2ctl configtest
Syntax OK
```

On an RPM-family system, run:

```console
$ sudo httpd -t
Syntax OK
```

Then confirm that httpd-rs can read the same configuration and certificates:

```console
$ sudo httpd-rsctl configtest
Syntax OK
```

`Syntax OK` means that httpd-rs can use the configured certificate and private
key. httpd-rs reads the existing certificate links below
`/etc/letsencrypt/live`. You do not need to copy the certificate files. If the
check reports an ownership or permission error, correct the path named in the
error before you switch services.

## 2. What changes during the service switch?

Run:

```console
$ sudo httpd-rs-switch
```

The command shows the Apache service that it found, the number of Certbot
renewal configurations, and the changes that it will make. Review the plan and
confirm the switch.

The switch makes two Certbot changes:

- Certbot's Apache commands control httpd-rs while httpd-rs is active. They
  control Apache again after a rollback.
- A successful certificate renewal reloads httpd-rs. A failed renewal does not
  reload the service.

The switch does not change the certificate paths or the Apache configuration.
If httpd-rs does not start, the command restores the previous Apache service
state. The [Apache rollback procedure](roll-back-to-apache.md) covers a later
manual rollback.

## 3. How do I verify an existing certificate?

Choose one domain name from the `certbot certificates` output. The following
command uses `www.example.test`; replace it with your domain name in both
places.

```console
$ openssl s_client -connect www.example.test:443 \
    -servername www.example.test </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Confirm that the subject alternative names contain the expected domains and
that the expiry date is current.

## 4. How do I issue a new certificate?

Skip this section when Certbot already manages every certificate that the site
needs.

The examples in this section use `www.example.test`. Replace it with the new
domain name before you run any command.

First, add an HTTP virtual host for the domain:

```apache
<VirtualHost *:80>
    ServerName www.example.test
    DocumentRoot /var/www/html
</VirtualHost>
```

On a Debian-family system, place the virtual host in
`/etc/apache2/sites-available`, enable it with `a2ensite`, and run
`httpd-rsctl configtest`. On an RPM-family system, place it in
`/etc/httpd/conf.d` and run `httpd-rsctl configtest`. Reload httpd-rs after the
configuration test succeeds.

Then ask Certbot to issue the certificate and add the TLS configuration:

```console
$ sudo certbot --apache -d www.example.test
```

Certbot tests the resulting configuration and reloads httpd-rs.

### If the configuration already refers to a missing certificate

`httpd-rsctl configtest` prints a `certbot certonly --standalone` command when
the configuration refers to certificate files that do not exist. The
standalone Certbot server needs port 80, so this procedure causes a brief
service interruption.

Replace the example domain in the printed command, then run:

```console
$ sudo systemctl stop httpd-rs.service
$ sudo certbot certonly --standalone -d www.example.test
$ sudo httpd-rsctl configtest
Syntax OK
$ sudo systemctl start httpd-rs.service
```

## 5. How do I verify future renewals?

Run one renewal test after the switch or after you issue a new certificate:

```console
$ sudo certbot renew --dry-run
$ sudo systemctl is-active httpd-rs.service
active
$ sudo journalctl -u httpd-rs.service --since today
```

The renewal test must succeed, and httpd-rs must remain active. After a real
successful renewal, Certbot reloads httpd-rs so that it begins serving the new
certificate.

<!--
Behavior contract evidence:
[Certbot package integration](../../tests/certbot_apache_integration.sh)
[Certbot service control](../../tests/certbot_apache_shim.sh)
[Package workflow](../../.github/workflows/artifacts.yml)
-->
