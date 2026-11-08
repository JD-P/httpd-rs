---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-JENKINS-001
scenario: jenkins-proxy
---

# Run the tested Jenkins reverse-proxy deployment

This tutorial runs Jenkins below `/jenkins/` and exercises authentication, a
CSRF-protected form operation, redirects, and session state through Vapache.

## What you will do

You will run the canonical `jenkins-proxy` deployment, create a Jenkins job,
reload Vapache, read the authenticated job API, and inspect the matching public
and backend prefixes.

## Before you start

You need Docker, 2048 MiB for the scenario, the Docker safety reserve, and root
or passwordless `sudo`.

## 1. Build and run the deployment

```console
$ cargo build --locked --release -p vapached
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario jenkins-proxy \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `mount=subpath`, `reload=after-start`, and
`benchmark=job`.

## 2. Verify the result

The final status must be `passed`. The workflow opens the login page,
authenticates, obtains a CSRF crumb and its session cookie, creates a job by
posting XML, reloads Vapache, and reads the protected job API.

## 3. Inspect the tested configuration

```console
$ find deployment-results -path '*jenkins-proxy-*' -name vapache.conf -print
```

The public `/jenkins/` route and the Jenkins backend context path match. This
prevents redirects and form targets from escaping the public mount.

## 4. Adapt the pattern

Configure the backend context path before you add the Vapache route. Verify a
state-changing request with its real authentication, cookie, and CSRF flow.
After reload, verify an authenticated object instead of the public login page.

## Clean up

The harness removes Jenkins, its state, and its private network. It retains the
configuration and semantic workflow result.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/jenkins-proxy/scenario.toml)
and [driver](../../tests/deployments/scenarios/jenkins-proxy/driver.py).
