---
doc_type: how-to
audience: service-operator
status: draft
contracts: DOC-HOWTO-SERVICE-001
---

# Reload, reopen logs, stop, and diagnose Vapache

Use this procedure for the packaged systemd service. Contract
`DOC-HOWTO-SERVICE-001` binds these commands to the packaged service definition
and reload tests.

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

The packaged `ExecReload` uses `vapachectl graceful`. Existing accepted
connections can complete against their current generation.

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

## Evidence

The [reload test](../../tests/vapachectl_reload.sh) checks wrapper configuration
selection and graceful reload behavior. The
[control-plane security test](../../tests/control_plane_security.sh) checks
privileged path and command selection. The packaged
[systemd unit](../../packaging/vapache.service) defines the start, preflight,
reload, and stop boundary. The [CLI lifecycle test](../../crates/server/tests/cli_lifecycle.rs)
checks reload and `SIGUSR1` log reopening. The
[configuration reload tests](../../crates/server/src/config.rs) check the
restart-only field comparison.
