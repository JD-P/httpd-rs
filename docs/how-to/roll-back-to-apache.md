---
doc_type: how-to
audience: apache-operator
status: draft
contracts: DOC-HOWTO-ROLLBACK-001
---

# Roll back to Apache

Use this procedure to return listener ownership to the Apache service after a
completed Vapache switch. Packaged tests exercise the interruption and
restoration steps.

## Prerequisites

Keep an administrative session that does not depend on the affected web
service. Confirm the Apache unit name. Debian-family systems normally use
`apache2.service`; RPM-family systems normally use `httpd.service`.

The original Apache configuration remains in place after `vapache-switch`.
The switch does not rewrite it.

## 1. Test Apache without starting it

Run the command for the installed service family:

```console
$ sudo apache2ctl configtest
Syntax OK
```

On an RPM-family system, use `sudo apachectl configtest`. Stop if the test
fails.

## 2. Stop Vapache

Run:

```console
$ sudo systemctl disable --now vapache.service
$ sudo ss -ltnp
```

Confirm that no Vapache process owns the HTTP or HTTPS listener.

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

The installed Certbot control shim selects Apache while Vapache is inactive.
Package removal removes the integration entries only when they still match the
Vapache-installed values.

## 5. Diagnose a failed rollback

If Apache does not start, inspect:

```console
$ sudo journalctl -u apache2.service -b --no-pager
$ sudo ss -ltnp
```

Check for another listener owner and for configuration changes made after the
original switch. Do not start both servers on the same address and port.

If `vapache-switch` failed before it reported success, it already attempts to
restore the prior active and enabled Apache state. Inspect both service units
before you repeat the transition.

## Evidence

The [Certbot Apache integration test](../../tests/certbot_apache_integration.sh)
interrupts switch operations and checks restoration of Apache's active and
enabled state. The [switch implementation](../../packaging/vapache-switch)
keeps the Apache configuration unchanged and restores the prior service state
when Vapache startup fails.
