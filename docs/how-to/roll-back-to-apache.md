---
doc_type: how-to
audience: apache-operator
status: draft
contracts: DOC-HOWTO-ROLLBACK-001
---

# Roll back to Apache

Use this procedure to return HTTP and HTTPS traffic to Apache after a completed
httpd-rs switch.

## Prerequisites

Keep a second SSH session or the hosting provider's console open during the
rollback. Confirm the Apache unit name. Debian-family systems normally use
`apache2.service`; RPM-family systems normally use `httpd.service`.

The original Apache configuration remains in place after `httpd-rs-switch`.
The switch does not rewrite it.

## 1. Test Apache without starting it

Run the command for the installed service family:

```console
$ sudo apache2ctl configtest
Syntax OK
```

On an RPM-family system, use `sudo httpd -t`. Stop if the test fails.

## 2. Stop httpd-rs

Run:

```console
$ sudo systemctl disable --now httpd-rs.service
$ sudo ss -ltnp
```

Confirm that no httpd-rs process owns the HTTP or HTTPS listener.

## 3. Start Apache

For Debian-family systems, run:

```console
$ sudo systemctl enable --now apache2.service
```

For RPM-family systems, run:

```console
$ sudo systemctl enable --now httpd.service
```

If Apache was not enabled before the migration, omit `enable` and use
`systemctl start`. Restore the service state that you recorded before the
switch.

## 4. Verify traffic and renewal control

Run:

```console
$ sudo systemctl status apache2.service
$ curl --fail --show-error --head http://www.example.test/
$ curl --fail --show-error --head https://www.example.test/
$ sudo certbot renew --dry-run
```

Use the RPM-family unit name where applicable. Test login, state changes,
uploads, proxy routes, and WebSockets that the site uses.

Certbot's Apache commands control Apache again while httpd-rs is inactive.

## 5. Diagnose a failed rollback

If Apache does not start, inspect:

```console
$ sudo journalctl -u apache2.service -b --no-pager
$ sudo ss -ltnp
```

Check for another listener owner and for configuration changes made after the
original switch. Do not start both servers on the same address and port.

If `httpd-rs-switch` failed before it reported success, it already attempts to
restore the prior active and enabled Apache state. Inspect both service units
before you repeat the transition.

<!--
Behavior contract evidence:
[Switch interruption](../../tests/certbot_apache_integration.sh)
[Switch implementation](../../packaging/httpd-rs-switch)
-->
