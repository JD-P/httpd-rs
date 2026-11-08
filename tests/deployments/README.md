# Real-application deployment tests

This suite deploys unmodified, well-known applications through Vapache. It is
an executable compatibility and operations library, not a replacement for the
protocol, differential, fuzz or unit suites.

## Profiles

- `nightly` runs one fixed representative case for Hugo static content, Git
  CGI, WordPress/PHP-FPM and Grafana HTTP/WebSockets.
- `canonical` runs the declared representative case for every application. It
  is the reproducible baseline for cross-application compatibility and
  differential performance campaigns.
- `sample` uses a recorded random seed. It first selects one random combination
  for every application (when the requested sample is large enough), then
  samples the remaining combinations without replacement.
- `full` is the explicit, expensive Cartesian escape hatch.

The application-integration workflow runs `nightly` from Monday through
Saturday. It runs `canonical` on Sunday so every application tutorial retains a
scheduled end-to-end behavior check.

Every combination has a nonzero chance of selection by `sample`. The emitted
`plan.json` records the exact seed, application versions and dimensions, so a
failure can be replayed exactly:

```sh
python3 tests/deployments/harness.py \
  --profile sample --sample-count 13 --seed 4660
```

Run one application while developing:

```sh
cargo build --release -p vapached
python3 tests/deployments/harness.py \
  --profile sample --scenario grafana-proxy --sample-count 1
```

Add `--benchmark` to start an equivalent Apache front end and collect three
alternating five-second samples from each server. Benchmarking requires
`apache2` and `wrk`; ordinary correctness runs do not start Apache.

The harness needs root or passwordless `sudo` so the daemon can drop to a
service identity distinct from the trusted release owner. This is part of the
security test, not merely a port-binding convenience.

## Container isolation

Applications use upstream OCI images directly as `repository@sha256:digest`
where possible. Compose supplies configuration, temporary volumes and a
private network to each immutable upstream image. Wagtail and Bugzilla need a
runtime assembled from upstream source; their source archives and extra build
inputs are digest-verified, their base image and Dockerfile frontend are
digest-pinned, and their build context is an independently staged directory
rather than the repository. The harness rejects unpinned build frontends and
build-context symlinks that escape staging.

Gitweb is a separate deliberate exception: CGI must execute as a local
process, so the scenario uses Ubuntu 24.04's maintained Git/Gitweb packages
and records the exact `git --version` with the result. This gives the nightly
test useful distro-integration drift rather than pretending a containerized
CGI process has the same ownership boundary.

The harness enforces these rules twice: once against the rendered Compose
model and again against the live container inspection.

- A bind source must be under the unique scenario run directory. Privileged
  runs default to `/run/vapache-deployments/...`, whose non-writable ancestry
  also satisfies the FastCGI stable-path policy; unprivileged developer runs
  must select an equivalently stable repository-external path explicitly.
- A bind source that contains or is contained by the repository is rejected.
- The Docker socket and privileged containers are rejected.
- Published application ports bind only to loopback; databases publish no
  host port.
- Containers use `no-new-privileges`, read-only root filesystems and dropped
  capabilities where their upstream entrypoints permit it.
- Networks are internal, and state lives only in scenario-owned bind paths or
  Compose volumes.
- Before each pull, the harness requires the scenario's declared unpacked-image
  budget plus 2 GiB of safety headroom on Docker's backing filesystem.
- Teardown captures logs and removes containers, networks and volumes after
  every case. Cases for one application are grouped so its image is pulled
  once; after the final selected case, only that scenario's exact pinned
  images are removed. The harness never invokes a global Docker prune.

The source checkout is therefore not writable—or even visible—to application
containers. Application code, generated content, databases and other mutable
state exist only in the staging directory or scenario-owned volumes.

## Result artifacts

Each case produces:

- the reproducible selection in `plan.json`;
- the exact tested Vapache configuration;
- Vapache and container logs;
- an Apache configuration and differential benchmark JSON when benchmarking;
- a final machine-readable status summary.

Configurations contain temporary absolute paths and ports, but their policy
sections are the tested reference for the deployment guides under
[`docs/deployments`](../../docs/deployments/README.md).

## Adding an application

An application directory contains `scenario.toml`, `driver.py`, and optional
Compose/configuration files. A driver must exercise a semantic workflow—not
only check that `/` returns 200—and must justify every enabled Vapache
capability. Images without an immutable digest are rejected at discovery.

Choose applications for distinct observable behavior rather than language
labels. Python, Java and Go look alike after becoming ordinary HTTP, while
WebDAV uploads, subpath redirects, smart Git HTTP and WebSocket lifetimes
exercise materially different server boundaries.
