# Deterministic transition fault campaign

## Objective

Exercise failures at cross-layer state transitions that ordinary unit tests
usually miss. A failed transition must not preserve authorization from the
wrong request, publish data under the wrong configuration/cache generation,
or leak a typed or physical resource reservation.

The `fault-injection` feature is test-only. Normal builds reduce checkpoints
to unconditional success and do not maintain a trace.

## Campaign mechanism

`fault::test_guard()` installs an isolated plan. A plan can fail a named
checkpoint or the Nth checkpoint in an execution trace. A successful run
therefore discovers its ordered transition trace, and a test can replay the
same operation once for every trace index.

Plans follow one operation across:

- Tokio tasks;
- Tokio blocking workers;
- the bounded HTTP/1 connection worker pool;
- native CGI and OCSP helper threads.

They are not process-global, so unrelated tests remain isolated under Rust's
parallel test runner. The inheritance test uses a multi-thread Tokio runtime
and crosses all three execution mechanisms. This caught and fixed a defect in
the initial test implementation: an `async fn` captured its plan when first
polled in the child task, rather than when the parent created the future.

## Instrumented security boundaries

| Boundary | Checkpoints and existing fault adapters |
| --- | --- |
| HTTP/1 request | admitted head, policy probe, body read/continue/backend-channel awaits |
| HTTP/1 response | output ownership transfer, socket-write and flush awaits, file/stream reads, sendfile wait |
| HTTP/2 request | admitted head, DATA/channel/trailer awaits, blocking policy/backend join |
| HTTP/2 response | output ownership transfer, flow-control capacity wait, file/stream reads |
| Dynamic backends | prepared-handler start; proxy and FastCGI connect/read/write/flush adapters |
| Processes | CGI worker/script spawn and worker I/O; RewriteMap spawn/read/write; TLS broker pre-fork and transport |
| Shared cache | store start and final generation-checked publication |
| Reload | final fallible precommit, before candidate background activation and old-generation retirement |
| Background work | inherited OCSP refresh start |

Post-fork child setup is deliberately not instrumented. Fault machinery uses
Rust synchronization and allocation, which are not async-signal-safe after a
multi-threaded process forks. Process faults are injected on the parent side
immediately before fork/exec instead.

## Asserted invariants

The campaign compares a complete process resource-ledger snapshot: every
typed slot and byte pool, aggregate descriptor/task/memory parents, disk
reservations on all devices, and transport-buffer ownership.

Current tests establish that:

1. every discovered HTTP/1 output checkpoint releases backend, descriptor,
   resident-memory, read, and output ownership;
2. HTTP/1 body-await failure drops the request-local reservation;
3. HTTP/2 body wait failures become a closed 503 path, and an inherited
   blocking-reader failure releases all response ownership;
4. a policy-transition failure cannot produce a prepared dynamic handler;
5. a backend-start failure drops the authorized CGI descriptor before any
   process side effect;
6. cache start/commit failures publish neither memory nor disk state and leak
   no cache-write or resident reservation;
7. reload precommit failure leaves the old generation admissible, while the
   subsequent successful commit retires it exactly once;
8. CGI, RewriteMap, TLS-broker, proxy, and FastCGI control/I/O failures are
   observable and fail closed.

## Result

No new production authorization, generation, cache, or lease violation was
found by the completed replays. The campaign did find an important blind spot
in the previous test infrastructure: thread-local failpoints stopped at task
and worker boundaries. Explicit inheritance closes that blind spot and makes
future sequence sweeps representative of the actual request topology.
