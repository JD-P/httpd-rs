---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-BUGZILLA-001
scenario: bugzilla-fastcgi
---

# Run the tested Bugzilla and generic FastCGI deployment

This tutorial runs Bugzilla through `fcgiwrap`. It demonstrates a generic
FastCGI application whose script identity, `PATH_INFO`, cookies, and protected
source files differ from a PHP-FPM deployment.

## What you will do

You will run the canonical `bugzilla-fastcgi` deployment, use the REST path-info
endpoint, complete Bugzilla's authenticated admin flow, reload Vapache, and
inspect the Unix-socket identity policy.

## Before you start

You need Docker, 2048 MiB for the scenario, the Docker safety reserve, and root
or passwordless `sudo`. The complete cold run can take 20 minutes.

## 1. Build and run the deployment

```console
$ cargo build --locked --release -p vapached
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario bugzilla-fastcgi \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `workflow=admin`, `session=authenticated`, and
`reload=after-login`.

## 2. Verify the result

The final status must be `passed`. The workflow completes the two-pass Bugzilla
setup, opens the application, denies Perl modules and `localconfig`, reads the
REST version endpoint through `PATH_INFO`, performs the login-request and CSRF
flow, opens administration policy, reloads Vapache, and confirms the session.

## 3. Inspect the tested configuration

```console
$ find deployment-results -path '*bugzilla-fastcgi-*' -name vapache.conf -print
```

The configuration enables `FastCgi`, registers the `fcgiwrap` Unix socket and
worker identity, maps `.cgi` plus path info, and denies direct reads of Perl
modules, templates, and local configuration. The socket is not a loopback TCP
endpoint.

## 4. Adapt the pattern

Identify the generic FastCGI runner separately from the application. Protect
the socket directory and authenticate the connected process. Keep executable
CGI and every ancestor immutable to the worker. Test an endpoint that requires
`PATH_INFO` and an authenticated state change.

## Clean up

The harness removes Bugzilla, `fcgiwrap`, MariaDB, staged images, volumes, and
the private network. It retains the tested configuration and setup logs.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/bugzilla-fastcgi/scenario.toml)
and [driver](../../tests/deployments/scenarios/bugzilla-fastcgi/driver.py).
