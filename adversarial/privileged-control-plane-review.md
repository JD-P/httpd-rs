# Privileged control-plane review

Date: 2026-11-04

## Scope and threat model

This campaign reviewed the code that runs with administrative authority but is
outside the Rust and Verus request-serving core:

- `vapachectl` configuration selection, snapshotting, capability generation,
  reload and lifecycle dispatch;
- `vapache-switch` service transition and Certbot migration;
- the Certbot Apache-control shim, deploy hook and package-removal cleanup;
- generated DEB/RPM maintainer scripts and the systemd unit; and
- the release package builder that emits those files.

The relevant attacker is a local identity able to influence a pathname,
environment, current configuration tree, or concurrent invocation without
already having root authority. Administrative mistakes and interruption at
every atomic transition are also in scope. The scripts are not setuid and do
not attempt to defend against an administrator intentionally executing
attacker-provided code as root.

## Findings and remediation

| ID | Pre-review behavior | Security effect | Remediation |
|---|---|---|---|
| CP-1 | Root helpers inherited `PATH` and shell startup variables; the Certbot shims accepted executable overrides without validating their identity or ancestor chain | A permissive sudo/hook environment or unsafe test/administrative override could select attacker code for a privileged command | Every installed script uses privileged shell mode, a fixed system path and clean startup variables. Executable overrides must be canonical, unsymlinked, executable, have an exact control-command basename, and be owned through a non-writable trusted path chain. The systemd unit removes loader/shell/language startup variables after its environment files are read |
| CP-2 | `vapachectl` recursively checked the selected configuration tree, but not the path components above `VAPACHE_CONFDIR`; it also accepted lexical `..`, symlinked roots and noncanonical main-config spellings | An apparently root-owned leaf below a replaceable ancestor could be swapped between validation and privileged snapshot copy | Root/config/runtime paths must be absolute, printable, canonical and unsymlinked. Every component is owned by root or the invoking identity and non-writable; only sticky trusted ancestors such as `/tmp` are allowed to be writable. The main config is proven below the canonical root |
| CP-3 | Snapshot invocations shared `apache-config`, `.previous` and temporary names without a process lock | Concurrent config tests, reloads or Certbot actions could move/delete one another's generation, test one tree and signal another, or leave the live snapshot missing | A controlled `/run/vapache/control.lock` serializes validation, copy, capability generation and lifecycle signaling. Temporary state is removed on normal failure and signals; recursive cleanup cannot cross mount points |
| CP-4 | Recursive dereferencing rejected escaping symlinks but did not reject FIFOs, devices, sockets or dangling links before `cp -RL` | A special entry in an administratively selected tree could block a root copy or enter the runtime configuration snapshot | Snapshot mode accepts only regular files and directories after dereferencing, and requires all copied objects to be controlled and non-writable. Non-snapshot RHEL layouts retain their native out-of-tree `logs`, `run` and `modules` links and are left to the daemon's descriptor-safe parser |
| CP-5 | `vapache-switch` restored Apache only on selected explicit failures; termination between stopping Apache and completing Vapache startup had no general rollback | An interrupted switch could leave both servers stopped or partially enabled | A separate switch lock prevents concurrent transitions. An EXIT/signal transaction records the original active/enabled state, disables a partial Vapache start, and restores exactly the prior Apache state until the Vapache start commits |
| CP-6 | Certbot directories were trusted mostly at the leaf file, temporary files were not uniformly signal-cleaned, and package cleanup permitted a broad caller-selected root | Replaceable directory components could redirect an atomic edit; interruption left temporary privileged data; a hostile cleanup environment widened the edit target | The fixed Certbot root, renewal and hook directories and every edited file must be canonical and controlled. Same-directory edits remain atomic, temporary files are signal-cleaned, hook replacement is exact, and privileged cleanup is limited to a dedicated `letsencrypt` root |
| CP-7 | DEB/RPM hook bodies established no execution environment, and the shared validation logic was not part of the package payload | Package-manager environment differences could alter command discovery, while fixes could diverge among five scripts | A root-owned `/usr/lib/vapache/control-common` centralizes path, owner, command and lock invariants. Archive, DEB and RPM payloads include it; every maintainer hook fixes its environment. `ProtectSystem=full` makes `/etc` and `/usr` read-only to the running service |

Certbot changes are individually atomic and idempotent. A signal before the
service transition may leave a safe subset of shim settings installed, but the
shim selects Apache whenever Vapache is inactive and the deploy hook is inert.
The next invocation completes the migration. Once Apache service state begins
changing, the rollback transaction is mandatory.

## Enforced invariants

```text
privileged command lookup = fixed PATH + exact basename + canonical executable
trusted(path)             = unsymlinked canonical spelling
                            + controlled target
                            + controlled/non-writable ancestor chain
snapshot input            = trusted regular files/directories only
snapshot mutation         = one holder of control.lock
service transition        = previous Apache state OR committed Vapache state
Certbot edit              = controlled parent + same-directory atomic rename
```

The wrapper validates only the whole tree it actually snapshots. Stock RHEL
`/etc/httpd` layouts are not copied and commonly contain intentional links to
`/var/log/httpd`, `/run/httpd` and the module directory; the Rust configuration
loader remains responsible for those non-snapshot inputs.

## Executable evidence

- `tests/control_plane_security.sh` exercises hostile `PATH`/startup files,
  command substitution through an unsafe ancestor, a replaceable configuration
  ancestor, special configuration entries, symlinked runtime state and two
  concurrent fixed-name snapshot swaps.
- `tests/certbot_apache_shim.sh` retains the strict read-only/lifecycle command
  grammar and now routes all test controls through validated executables.
- `tests/certbot_apache_integration.sh` installs the real package, interrupts
  the switch during Apache shutdown, and requires Vapache cleanup plus exact
  Apache enabled/active restoration before completing a successful migration;
  it also requires installed helpers to reject a writable shared library.
- `tests/vapachectl_reload.sh` continues to prove that a snapshot-backed
  graceful reload observes changed Apache policy.
- The artifact workflow inspects and installs the archive/DEB/RPM payloads,
  including the shared control library, on the supported distribution targets.

## Residual boundaries

- A shell cannot remove `LD_PRELOAD` before its own dynamic interpreter is
  loaded. The systemd unit explicitly removes loader variables, package
  managers and ordinary sudo policy sanitize them, and `-p` prevents shell
  startup-file/function import. Any alternate root launcher must provide the
  same loader-environment guarantee; control scripts are deliberately not a
  privilege-elevation interface.
- Certbot itself does not share Vapache's switch lock. A separate root Certbot
  process can race an administrator running `vapache-switch`; each file remains
  atomic and valid, but administrators should serialize those two root-level
  operations.
- The common shell predicates are executable security checks, not Verus proofs.
  Their narrow inputs and ownership matrix are pinned by the control-plane
  regression suite and installed-package integration.
