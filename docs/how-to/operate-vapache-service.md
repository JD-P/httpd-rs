---
doc_type: how-to
audience: service-operator
status: draft
contracts: DOC-HOWTO-SERVICE-001
---

# Reload, reopen logs, stop, and diagnose Vapache

Use this procedure for the packaged systemd service.

## Prerequisites

Install the Vapache package and use a systemd-based host. Obtain administrative
access and the configured error-log path.

## Check service state

Run:

```console
$ sudo systemctl status vapache.service
$ sudo vapachectl status
$ sudo journalctl -u vapache.service --since today
```

If the service is inactive, run the configuration test before you start it:

```console
$ sudo vapachectl configtest
$ sudo systemctl start vapache.service
```

## Reload configuration

Run the test and reload:

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
```

Existing accepted connections can complete with the configuration that
accepted them. New connections use the reloaded configuration.

Vapache rejects reload-only changes to the process identity, listeners, PID
file, server root, listen backlog, and CGI execution policy. When the
diagnostic requires a restart, run:

```console
$ sudo systemctl restart vapache.service
```

Plan the restart as a listener interruption.

## Reopen log files

Rotate configured log files. Then signal only the service main process:

```console
$ sudo systemctl kill --kill-who=main --signal=USR1 vapache.service
```

Vapache reopens its configured logs after `SIGUSR1`. Confirm that new requests
write to the new file. Do not use a process-name pattern to send the signal.

## Stop the service

For a managed service, run:

```console
$ sudo systemctl stop vapache.service
```

For direct control outside systemd, use `sudo vapachectl graceful-stop`.
Confirm that the listener is closed and that the command completes within the
service stop timeout.

## Diagnose a failed start or reload

Run these checks in order:

```console
$ sudo vapachectl configtest
$ sudo systemctl status vapache.service
$ sudo journalctl -u vapache.service -b --no-pager
$ sudo ss -ltnp
```

Use the first Vapache diagnostic as the primary finding. Check whether Apache
or another service owns a configured listener. Check the configured error log
when the journal reports that the server reached its logging stage.

If the diagnostic names an unsupported directive, use
[Investigate a rejected directive](investigate-rejected-directive.md). If it
names a missing capability or unsafe input, use
[Assess an Apache configuration](assess-apache-configuration.md).

<!--
Behavior contract evidence:
[Reload behavior](../../tests/vapachectl_reload.sh)
[Control path checks](../../tests/control_plane_security.sh)
[Packaged service](../../packaging/vapache.service)
[CLI lifecycle](../../crates/server/tests/cli_lifecycle.rs)
[Reload validation](../../crates/server/src/config.rs)
-->
