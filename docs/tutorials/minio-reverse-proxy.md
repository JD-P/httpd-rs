---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-MINIO-001
scenario: minio-proxy
---

# Run the tested MinIO reverse-proxy deployment

This tutorial sends S3 Signature Version 4 requests through Vapache to MinIO.
The signature covers the public authority, so the canonical deployment
preserves the validated `Host` field.

## What you will do

You will run the canonical `minio-proxy` deployment, stream a signed upload,
reload Vapache, download and range the object, list the bucket, and remove the
test data.

## Before you start

You need Docker, 1024 MiB for the scenario, the Docker safety reserve, and root
or passwordless `sudo`.

## 1. Build and run the deployment

```console
$ cargo build --locked --release -p vapached
$ python3 tests/deployments/harness.py \
    --profile canonical \
    --scenario minio-proxy \
    --vapached target/release/vapached \
    --artifacts deployment-results
```

The canonical dimensions are `payload=streaming`, `operation=listing`, and
`reload=before-read`.

## 2. Verify the result

The final status must be `passed`. The workflow creates a bucket, sends an
approximately 1 MiB SigV4 streaming upload, reloads Vapache, checks the exact
download and one range, lists the object, and deletes the object and bucket.

## 3. Inspect the tested configuration

```console
$ find deployment-results -path '*minio-proxy-*' -name vapache.conf -print
```

The configuration uses `ProxyPreserveHost On`. MinIO verifies the same public
authority that the client signed. The backend address remains private.

## 4. Adapt the pattern

Preserve the public authority only when the backend requires it. Verify a real
signed operation after the proxy is in place. Include a streaming body, a range,
and a listing because a health endpoint does not exercise signature identity or
response streaming.

## Clean up

The workflow deletes its S3 object and bucket. The harness removes MinIO and its
private network and retains the test evidence.

## Evidence

The automated deployment test uses the
[scenario manifest](../../tests/deployments/scenarios/minio-proxy/scenario.toml)
and [driver](../../tests/deployments/scenarios/minio-proxy/driver.py).
