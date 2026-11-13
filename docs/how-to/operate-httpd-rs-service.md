---
doc_type: how-to
audience: service-operator
status: draft
contracts: DOC-HOWTO-SERVICE-001
---

# Reload, reopen logs, stop, and diagnose httpd-rs

Use this procedure for the packaged systemd service.

## Prerequisites

Install the httpd-rs package and use a systemd-based host. Obtain administrative
access and the configured error-log path.

## Check service state

Run:

```console
$ sudo systemctl status httpd-rs.service
$ sudo httpd-rsctl status
$ sudo journalctl -u httpd-rs.service --since today
```

If the service is inactive, run the configuration test before you start it:

```console
$ sudo httpd-rsctl configtest
$ sudo systemctl start httpd-rs.service
```

## Reload configuration

Run the test and reload:

```console
$ sudo httpd-rsctl configtest
$ sudo systemctl reload httpd-rs.service
```

Existing accepted connections can complete with the configuration that
accepted them. New connections use the reloaded configuration.

httpd-rs rejects reload-only changes to the process identity, listeners, PID
file, server root, listen backlog, and CGI execution policy. When the
diagnostic requires a restart, run:

```console
$ sudo systemctl restart httpd-rs.service
```

Plan the restart as a listener interruption.

## Reopen log files

Rotate configured log files. Then signal only the service main process:

```console
$ sudo systemctl kill --kill-who=main --signal=USR1 httpd-rs.service
```

httpd-rs reopens its configured logs after `SIGUSR1`. Confirm that new requests
write to the new file. Do not use a process-name pattern to send the signal.

## Stop the service

For a managed service, run:

```console
$ sudo systemctl stop httpd-rs.service
```

For direct control outside systemd, use `sudo httpd-rsctl graceful-stop`.
Confirm that the listener is closed and that the command completes within the
service stop timeout.

## Diagnose a failed start or reload

Run these checks in order:

```console
$ sudo httpd-rsctl configtest
$ sudo systemctl status httpd-rs.service
$ sudo journalctl -u httpd-rs.service -b --no-pager
$ sudo ss -ltnp
```

Use the first httpd-rs diagnostic as the primary finding. Check whether Apache
or another service owns a configured listener. Check the configured error log
when the journal reports that the server reached its logging stage.

If the diagnostic names an unsupported directive, use
[Investigate a rejected directive](investigate-rejected-directive.md). If it
names a missing capability or unsafe input, use
[Assess an Apache configuration](assess-apache-configuration.md).

<!--
Behavior contract evidence:
[Reload behavior](../../tests/httpd-rsctl_reload.sh)
[Control path checks](../../tests/control_plane_security.sh)
[Packaged service](../../packaging/httpd-rs.service)
[CLI lifecycle](../../crates/server/tests/cli_lifecycle.rs)
[Reload validation](../../crates/server/src/config.rs)
-->
