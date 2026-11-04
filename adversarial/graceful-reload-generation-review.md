# Graceful reload and configuration-generation isolation review

## Scope

This campaign followed every object which can outlive the listener loop that
accepted it: HTTP/1 keep-alive transports, HTTP/2 connections and streams,
WebSocket tunnels, in-flight shared-cache writes, parsed access files, proxy
health/failure observations, TLS/OCSP generations, logs, listeners and the
process-wide resource hierarchy.

The required transition is:

1. parse and validate a candidate without changing the live generation;
2. prepare every fallible candidate resource;
3. commit one candidate cache epoch and retire the old generation;
4. admit new transports only under the candidate;
5. let already-admitted finite requests finish under their immutable old
   `Config`, while refusing every new request/stream/tunnel operation there.

A rejected candidate stops listener admission only while it is checked. It
does not retire the still-current generation.

## Findings and remediation

### RGI-1: retired transports continued to admit stale policy

`Server::run` stopped accepting sockets on SIGHUP, but accepted HTTP/1
keep-alive connections and HTTP/2 connections owned only an `Arc<Config>`.
They could begin requests indefinitely after a successful allow-to-deny,
authentication, route or TLS-policy reload. WebSocket tunnels likewise had no
generation revocation signal.

Configuration generations now own a clone-shared retirement flag distinct
from the listener-stop flag. This distinction matters after a rejected
reload: every resumed listener loop around the same `Config` shares the same
eventual retirement identity. The flag is distributed through one event-driven
watch channel, so idle H2 and WebSocket connections do not poll or create a
per-connection timer load. H1/H2 admission executes under a generation-local
read gate; commit takes the write side before setting the flag. A request or
stream therefore linearizes wholly before retirement or fails after it, with
no check/commit window. At a successful commit:

- HTTP/1 finishes an admitted response, forces close, and refuses a head read
  after retirement before dispatch;
- HTTP/2 sends GOAWAY, refuses newly observed streams and drives already
  admitted stream tasks to completion;
- TLS/prelude admissions stop before HTTP dispatch if their generation was
  retired; and
- WebSocket setup checks retirement before emitting 101, while established
  tunnels close promptly on retirement.

`configuration_generation_admit` and
`retired_configuration_generation_rejects_new_work` mechanize the admission
predicate used by both protocol adapters and WebSocket ownership.

### RGI-2: an old request could publish into the new cache epoch

Cache stores labeled an entry with the process-global epoch at completion. An
old request completing after reload therefore observed the new epoch and
could publish an old-generation representation as new. Merely ordering the
epoch bump and retirement cannot close this race: a request can linearize on
either side between the two atomics.

Each immutable `Config` now owns a clone-shared cache-epoch cell. A request
captures that generation's epoch when its cache policy is planned, and lookup
and store require equality with that same config-owned cell. Entries are
labeled with the request's captured epoch, never a global value sampled at
completion. The final store publication and reload cleanup share a read/write
generation barrier: commit retires the old cell, advances the candidate cell,
and clears both roots while holding the write side. Consequently, an older
store either finishes before cleanup or is rejected; it cannot recreate files
on an abandoned `CacheRoot`. Unsafe-method invalidation likewise updates the
live config's shared cell. Commit closes the configuration-admission gate
before taking this cache barrier, so an established old transport cannot admit
a fresh store-capable request during cleanup.

`cache_generation_admit` and `stale_cache_generation_rejects_work` prove the
epoch equality gate.

### RGI-3: `.htaccess` IR crossed main-configuration generations

The access-file parse cache bound file identity, metadata, override mode and
mapping identity, but not the main `Config`. Parsing can evaluate `IfDefine`
and capability gates, so an unchanged `.htaccess` file could reuse policy
compiled under the previous generation. A removed `Define` could therefore
leave a cached grant active.

The parse-cache key now includes the immutable configuration-generation ID.
The last `Config` clone removes that generation's parsed access policy, proxy
health/failure observations and round-robin counters, keeping reload state
bounded without deleting data while an old request can still consume it.

### RGI-4: active proxy health state was process-global

Candidate background activation stopped the old health worker and cleared
process-global health/dead maps before old in-flight proxy requests had
finished. Equal balancer/member names allowed those requests to consume
candidate observations.

Health, passive-failure and selection-counter keys now include the immutable
configuration-generation ID. Old observations remain available until the
last old `Config` clone drops; candidate state cannot alias them. Starting an
identical candidate still creates its own worker namespace.

## Regression evidence

- `foreground_reload_reopen_bind_and_actions` keeps one HTTP/1 connection
  across a rejected candidate, proves it remains usable, then proves the same
  socket cannot dispatch old policy after a successful DocumentRoot reload.
- `retired_h2_generation_refuses_new_streams` retires while an admitted body
  remains flow-control blocked, proves that body drains completely, and
  requires a later stream to fail.
- `websocket_tunnel_closes_when_generation_retires` proves a live tunnel is
  interrupted independently of its idle deadline.
- `production_store_rejection_and_eviction_edges` exercises a store carrying
  a stale captured cache epoch.
- `access_file_cache_is_partitioned_by_configuration_generation` parses one
  unchanged access file with and without `Define PROD` and proves the second
  generation cannot reuse the first IR.
- `backend_health_and_failure_state_is_generation_scoped` proves active and
  passive routing observations do not alias across generation IDs.
- `generation_retirement_linearizes_after_admission_readers` proves commit
  waits for an admission decision holding the read side and rejects later
  decisions.

TLS listener configuration, certificate resolvers and OCSP refreshers were
already generation-owned. OCSP workers retain weak generation references and
therefore required no new cross-generation mutable state. The resource budget
remains intentionally process-shared, so overlapping generations cannot reset
or double-spend capacity.

The remaining mutable-static inventory was reviewed for omitted policy keys.
The authentication cache is keyed by stable file identity and parses no
configuration-dependent semantics; proxy DNS entries are pure host/port
resolution; OCSP entries bind certificate chain plus responder URL; and H2
buffer pools contain only cleared byte storage. The CGI pool's only persistent
policy inputs are `User` and `Group`, both already rejected on graceful reload,
while `RewriteMap prg` programs remain owned by their immutable `Config`.
Telemetry, log serialization, resource budgets and physical-capacity ledgers
are deliberately process-wide rather than policy-bearing.
