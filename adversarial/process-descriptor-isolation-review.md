# Process and descriptor isolation review

This campaign reviewed every process Vapache creates or retains across
requests: the main daemon, local CGI worker pool and scripts, `RewriteMap prg`
helpers, the privileged TLS file broker, and the adjacent disposable DNS
workers. The security objective is an explicit process tree and an explicit
descriptor set, with startup failing closed if either cannot be established.

## Findings

| Boundary | Pre-review behavior | Remediation |
|---|---|---|
| Main daemon | Launcher-supplied descriptors could survive daemonization; `/dev/null`, `dup2`, and `chdir` failures were ignored; background threads were activated before the root process finished creating helpers and dropping privilege | Close every descriptor above stderr before parsing configuration; require every daemonization syscall; use umask `027`; create the TLS broker and CGI pool while single-threaded; activate OCSP/cache/health work only after the permanent uid/gid transition |
| CGI admission | A missing or saturated worker pool silently fell back to spawning from the multithreaded daemon, temporarily making an authorized script descriptor inheritable process-wide | Production CGI always uses the pre-created pool; unavailable or saturated capacity returns `503`; a reload may not enable CGI when no pool exists |
| CGI worker | Numeric users retained root supplementary groups; `initgroups` failure was ignored; uid/gid 0 was accepted; a partial pool startup could leave earlier workers alive | Reject uid/gid 0, require supplementary-group setup, clear groups for numeric users, use irreversible `setresgid`/`setresuid`, signal readiness only after isolation, and terminate every partial-pool worker on failure |
| CGI script | Child setup did not sweep unrelated descriptors, and descendants could retain pipes/control resources beyond a successful response | Mark all descriptors above stderr close-on-exec in the child, restore only the inode-bound script descriptor, bind the child to its worker, create a session, set no-new-privileges/core/CPU/file/descriptor limits, and kill the process group after every completion path |
| `RewriteMap prg` | Helpers inherited the daemon environment and any accidentally inheritable descriptor; a reader thread could wait forever on stdout retained by a descendant | Use an empty environment with a fixed system `PATH`; restore only the sealed program descriptor; apply parent binding, session, no-new-privileges, core/CPU/file/descriptor limits; read bounded nonblocking output to an absolute deadline; always kill the helper process group |
| TLS broker | A failed `close_range` fell back to closing only descriptors below 65,536, and the parent could begin using the broker without proof that hardening completed | Fail closed on an unavailable descriptor sweep; keep only protocol fd 3; send readiness only after descriptor closure, rlimits, dump protection, no-new-privileges, and seccomp; kill and reap a broker that misses the readiness deadline |
| DNS helpers | The daemon environment crossed the helper boundary | Clear the environment and close all inherited descriptors immediately in each hidden worker entrypoint |

## Enforced invariants

```text
fds(daemon at entry)       = {0, 1, 2}
fds(cgi worker after exec) = {0, 1, 2, control_fd}
fds(cgi script after exec) subseteq {0, 1, 2, authorized_script_fd}
fds(rewrite helper)        subseteq {0, 1, 2, sealed_program_fd}
fds(tls broker)            = {protocol_fd}

CGI execution enabled => isolated pool ready before request threads
helper ready => privilege, descriptor, lifetime, and resource limits installed
pool unavailable or saturated => 503, never direct-spawn downgrade
group cleanup => signal while direct child PID is owned and unreaped
```

Linux `close_range(2)` supplies the atomic descriptor sweep. Vapache does not
use a guessed upper-fd loop: failure means startup/helper failure. This makes
Linux 5.9 the minimum supported kernel (the earlier `openat2` boundary needed
5.6).

The libc/syscall work is centralized in `process.rs`; the intentionally added
unsafe sites and the fork/exec probes were reviewed into
`docs/unsafe-baseline.json`. The same update ratchets the `files.rs` and
`server.rs` allowances down to their smaller current boundaries.

## Executable evidence

- `process::tests::cloexec_sweep_preserves_only_an_explicitly_restored_descriptor`
  checks the shared child-side primitive in a disposable process.
- `process::tests::exited_child_can_be_observed_without_reaping_or_releasing_its_pid`
  pins the `waitid(WNOWAIT)` ownership rule used before process-group cleanup,
  preventing a reaped child PID from being recycled as an unrelated PGID.
- `cgi::tests::cgi_exec_closes_an_unrelated_inheritable_descriptor` deliberately
  clears CLOEXEC on a sentinel and verifies it is absent after script exec.
- `rewrite::tests::maps_backrefs_and_url_helpers` verifies both descriptor and
  environment isolation in the executed helper.
- `tls::tests::privileged_broker_reports_ready_only_after_descriptor_isolation`
  checks the real broker fork/seccomp path and observes the sentinel's absence
  before the readiness byte.
- `cli_lifecycle::foreground_reload_reopen_bind_and_actions` injects a fixed
  non-CLOEXEC descriptor in `pre_exec` and verifies the live daemon did not
  retain it.
- CGI pool tests pin fail-closed `503` exhaustion and partial-start cleanup;
  reload tests require a full restart before changing from static-only to CGI.

## Boundary that remains external

Vapache is not a general CGI sandbox. CGI code runs as the configured service
identity and may use the syscalls available to that identity. Ordinary child
processes remain in the per-request process group and are killed, while output
and input ownership has an absolute deadline even if a descendant deliberately
creates a new session. Deployments that execute mutually untrusted CGI code
still need an OS isolation boundary (separate uid/container/cgroup). FastCGI
and reverse-proxy application processes are separately managed services; this
campaign isolates Vapache's sockets and request accounting but does not change
their service-manager policy.
