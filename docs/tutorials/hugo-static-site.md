---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-HUGO-001
scenario: hugo-static
---

# Run the tested Hugo static-site deployment

This tutorial builds a Hugo site and serves the generated files directly from
Vapache. The canonical case adds Basic authentication, Brotli compression, a
disk cache, an access-file rule, and a graceful reload.

## What you will do

You will:

1. build Vapache;
2. run the canonical `hugo-static` deployment;
3. inspect the exact generated configuration;
4. identify the controls to retain in another static-site deployment.

## Before you start

You need Docker, 768 MiB for the image and scenario, the Docker safety reserve,
and root or passwordless `sudo`. The harness pulls a digest-pinned Hugo image.

## 1. Build Vapache

```console
$ cargo build --locked --release -p vapached
```

## 2. Run the canonical deployment

```console
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario hugo-static \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `access=basic`, `cache=disk`, `encoding=brotli`,
and `reload=after-start`.

## 3. Verify the result

The final harness status must be `passed`. The workflow verifies:

- the generated home page and post;
- an access-file redirect and response header;
- the custom `404` page;
- rejection and acceptance for the protected directory;
- Brotli output and a byte range;
- a disk-cache hit;
- the generated site after reload.

## 4. Inspect the tested configuration

Find the saved configuration:

```console
$ find deployment-results -path '*hugo-static-*' -name vapache.conf -print
```

The configuration enables `AccessFiles` because this lab tests `.htaccess`.
Keep that capability off when all policy is in the main configuration. Limit
cache policy to generated static assets. Keep private paths outside public
cache policy.

## 5. Adapt the pattern

Build the site separately from Vapache. Deploy the generated output as an
immutable release tree. Point `DocumentRoot` at the current release and retain
the explicit authorization, compression, cache, range, and error-page checks
that your site needs.

## Clean up

The harness removes its containers, network, volumes, and selected image. It
retains `plan.json`, `summary.json`, the Vapache configuration, and logs below
`deployment-results`.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/hugo-static/scenario.toml)
and [driver](../../tests/deployments/scenarios/hugo-static/driver.py).
