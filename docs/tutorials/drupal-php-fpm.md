---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-DRUPAL-001
scenario: drupal-fpm
---

# Run the tested Drupal and PHP-FPM deployment

This tutorial installs Drupal through PHP-FPM and executes Drupal's adapted
`.htaccess` policy. The canonical case uses the Umami profile, a clean URL, and
a reload after startup.

## What you will do

You will run the canonical `drupal-fpm` deployment, verify public and protected
files, inspect the bounded access-file adaptations, and review the stable
FastCGI path.

## Before you start

You need Docker, 1536 MiB for the scenario, the Docker safety reserve, and root
or passwordless `sudo`.

## 1. Build and run the deployment

```console
$ cargo build --locked --release -p vapached
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario drupal-fpm \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `profile=demo_umami`, `reload=after-start`, and
`benchmark=clean-url`.

## 2. Verify the result

The final status must be `passed`. The workflow completes the Drupal installer,
opens the site and login page, denies `composer.json`, prevents direct access to
`.htaccess`, reloads Vapache, and opens the login page again.

## 3. Inspect the tested configuration

```console
$ find deployment-results -path '*drupal-fpm-*' -name vapache.conf -print
```

The configuration enables `AccessFiles` and `FastCgi`, registers the PHP-FPM
Unix socket, and allows Drupal's access file. The scenario changes four bounded
upstream constructs. Its adapter fails when those exact source lines drift.

## 4. Adapt the pattern

Give your coding agent the `.htaccess` file from the exact Drupal release, the
Vapache configuration-test output, and the tested configuration from step 3.
Ask it to list each adapted rule, the behavior that the rule preserves, and a
request that tests the behavior. Do not accept an adaptation that only deletes
an unsupported directive.

Keep Drupal code immutable to PHP-FPM. Leave only the documented files
directory writable and deny executable handlers there.

## Clean up

The harness removes Drupal and its private resources. It retains the tested
configuration, adapted source evidence, plan, summary, and logs.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/drupal-fpm/scenario.toml)
and [driver](../../tests/deployments/scenarios/drupal-fpm/driver.py).
