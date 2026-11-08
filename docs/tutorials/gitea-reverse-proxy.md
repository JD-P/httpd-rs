---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-GITEA-001
scenario: gitea-proxy
---

# Run the tested Gitea reverse-proxy deployment

This tutorial runs Gitea below `/gitea/`. It exercises API request bodies and
Git smart HTTP through the same Vapache reverse-proxy route.

## What you will do

You will run the canonical `gitea-proxy` deployment, create a repository through
the API, reload Vapache, push a commit, clone the repository, and inspect the
subpath route.

## Before you start

You need Docker, Git, 1536 MiB for the scenario, the Docker safety reserve, and
root or passwordless `sudo`.

## 1. Build and run the deployment

```console
$ cargo build --locked --release -p vapached
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario gitea-proxy \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `mount=subpath`, `reload=before-transfer`, and
`benchmark=repository`.

## 2. Verify the result

The final status must be `passed`. The workflow reads the version API, checks
that redirects do not expose the backend, creates a repository, reloads
Vapache, pushes a commit through smart HTTP, clones it, and compares the file.

## 3. Inspect the tested configuration

```console
$ find deployment-results -path '*gitea-proxy-*' -name vapache.conf -print
```

Gitea's public `ROOT_URL` includes `/gitea/`. The Vapache route removes that
public prefix when it sends the request to Gitea's root router. The route must
preserve request and response streaming for Git transfers.

## 4. Adapt the pattern

Set the public application URL and subpath first. Confirm how the backend router
handles the prefix before you select the `ProxyPass` target. Verify a push and a
clone; an API health response does not exercise smart-HTTP bodies or streaming.

## Clean up

The harness removes Gitea, its state, and its private network. It retains the
tested configuration and result artifacts.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/gitea-proxy/scenario.toml)
and [driver](../../tests/deployments/scenarios/gitea-proxy/driver.py).
