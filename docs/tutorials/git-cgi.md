---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-GIT-CGI-001
scenario: git-cgi
---

# Run the tested Gitweb and smart Git HTTP deployment

This tutorial runs Gitweb and `git-http-backend` through Vapache's CGI worker
pool. The canonical case protects both routes with Basic authentication, clones
a real repository, and reloads Vapache.

## What you will do

You will build Vapache, run the canonical `git-cgi` deployment, inspect the CGI
configuration, and identify the executable and repository trust boundaries.

## Before you start

You need Git, Perl, Gitweb, `libcgi-pm-perl`, 512 MiB of free scenario storage,
and root or passwordless `sudo`. On Ubuntu 24.04, install matching `git` and
`gitweb` package versions.

## 1. Build Vapache

```console
$ cargo build --locked --release -p vapached
```

## 2. Run the canonical deployment

```console
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario git-cgi \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `application=smart-http`, `access=basic`, and
`reload=after-start`.

## 3. Verify the result

The final status must be `passed`. The workflow verifies Gitweb pages, rejects
unauthenticated requests, checks the smart-HTTP advertisement, performs a real
clone, compares the cloned marker, reloads Vapache, and checks Gitweb again.

## 4. Inspect the tested configuration

```console
$ find deployment-results -path '*git-cgi-*' -name vapache.conf -print
```

The configuration enables only the `Cgi` capability for execution. It fixes
`GITWEB_CONFIG`, `GIT_PROJECT_ROOT`, and `GIT_HTTP_EXPORT_ALL` in configuration.
No request value becomes an executable path or repository root.

## 5. Adapt the pattern

Keep CGI executables and repository administration outside the service
identity's mutation authority. Give each CGI route an explicit directory and
authorization policy. Verify a semantic operation, such as clone or fetch,
rather than accepting one successful HTML response.

## Clean up

The harness stops Vapache and removes the temporary repositories. It retains
the exact Git and package versions, configuration, plan, summary, and logs.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/git-cgi/scenario.toml)
and [driver](../../tests/deployments/scenarios/git-cgi/driver.py).
