# HTTP/2 stream lifecycle and cancellation review

- **Campaign:** HTTP/2 stream ownership, reset/connection-close cancellation,
  request trailers, backend lifetime, generation retirement and response flow
  control
- **Date:** 2026-11-04
- **Disposition:** remediated; retained unit, integration and Verus regressions

## Scope

This review followed a stream from pre-spawn admission through request-body
acquisition, blocking policy evaluation, CGI/FastCGI/proxy execution, response
flow control, reset reclamation and connection or configuration-generation
shutdown.  It specifically tested the cases in which the HTTP/2 transport
stops being a useful owner while synchronous backend work is still running.

## Findings and remediation

### H2-L1: a connection could outlive its ownership of detached stream tasks

Accepted streams were started with `tokio::spawn`.  An `h2` connection error
or abrupt transport close could return from the connection driver while a
request task, and therefore a proxy or executable backend, continued running.
The task would eventually encounter its ordinary backend timeout, but it no
longer had a live protocol owner and retained resource capacity in the
meantime.

The connection now owns every accepted task in a `JoinSet`.  A request scope
is created at admission, before any task is spawned, and an RAII cancellation
guard travels with the task.  Every connection-loop outcome is captured and
then passes through one epilogue which aborts and joins the task set.  Dropping
the guard cancels the shared request scope, so request-body and synchronous
backend clones observe the same terminal state.

### H2-L2: a client reset was not observable during blocking request phases

Body-policy probes, final dispatch and the wait for a dynamic backend used
`spawn_blocking(...).await`.  During those awaits the adapter did not poll
`SendResponse::poll_reset`, so an RST_STREAM could leave backend work and its
leases active until a normal response or timeout.

Those waits now race the blocking task against the stream reset.  A reset
cancels the request scope immediately.  Proxy and FastCGI DNS/connect/exchange
loops plus pooled and local CGI transport loops check that scope at bounded
intervals.  A canceled pooled CGI exchange terminates the worker process group
instead of returning possibly desynchronized protocol state to the pool.

The regression pass also caught a subtle cancellation bug while implementing
this rule: `Read::read_exact` and `Write::write_all` automatically retry
`ErrorKind::Interrupted`.  Reporting cancellation as `Interrupted` therefore
made the new CGI cancellation path loop indefinitely.  Cancellation now uses
the terminal `ConnectionAborted` kind in CGI, FastCGI and proxy transports.

### H2-L3: request trailers bypassed Vapache's trailer policy

The adapter stopped after the DATA stream and never called
`RecvStream::trailers`.  An HTTP/2 peer could consequently send a trailer block
which was neither rejected by the default-off `RequestTrailers` capability nor
validated by Vapache's routing/framing-field policy.

Both buffered and streamed request bodies now consume the terminal trailer
block within the body deadline.  Non-empty trailers require the
`RequestTrailers` capability, are capped at 64 fields and 64 KiB, and pass the
same forbidden-field validation used for HTTP/1 chunked trailers.  In
particular, framing and routing fields cannot be smuggled into the request's
terminal metadata.

### H2-L4: the formal lifecycle made ordinary completion depend on reset
reclamation

The previous model sent every active stream through `AwaitingReset` on its
normal end event.  That conflated ordinary completion with the deliberately
delayed reset tombstone and did not model connection close.

The executable/refinement model now distinguishes `Finish`, `Reset`,
`Reclaim`, and `ConnectionClose`.  Verus proves that normal completion closes
directly, reset closes after reclamation, connection close terminates every
admitted phase, and a closed stream cannot reopen.  The runtime accounting
path consumes the executable transition rather than keeping the proof model
disconnected from the adapter.

## Retained checks

The HTTP/2 suite now exercises 40 adapter tests, including:

- reset of a stalled proxy while an unrelated stream on the same connection
  completes;
- abrupt connection close while a backend is stalled, followed by resource
  and transport-drain assertions;
- normal, reset, timeout, size-limit, declared-length, backend-close,
  backend-stall, minimum-rate and trailer outcomes for streamed request bodies;
- default-off, enabled, forbidden-field and count-bound trailer behavior;
- tiny response windows across byte, stream and every file-transfer strategy;
- response-buffer reuse limits and configuration-generation retirement during
  an incomplete HTTP/2 handshake;
- cancellation checkpoints in proxy, FastCGI, pooled CGI and local CGI.

An isolated instrumented run of `h2::tests` covers 90.95% of all source lines
in `h2.rs`.  On the production-only metric used by the security coverage
ratchet it covers 1,202 of 1,395 executable lines (86.16%), up from 82.33% for
the same isolated corpus before this campaign.  The remaining isolated gaps
are predominantly process-wide exhaustion responses, blocking-task panic
recovery, dependency-owned malformed-state branches and TLS-only entry paths;
the full coverage corpus exercises additional real-daemon paths.

Verus reports 702 verified obligations and zero errors after the lifecycle
model expansion.

