# Filesystem identity and TOCTOU review

Date: 2026-11-03

## Scope and invariant

This pass reviewed every production filesystem observation that can influence
request routing, authorization, content disclosure, executable selection, or a
privileged administrative input. The attacker models were a remote request
controlling a path or expression operand, a content/.htaccess author able to
rename entries below a mapping root, and the unprivileged service account able
to mutate its own files while a privileged configuration generation is loaded
or reloaded.

The resulting invariant is:

1. A request-controlled path is resolved relative to a retained mapping-root
   descriptor with `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)`.
2. A policy decision about an object is consumed through that opened object,
   or the pathname is reopened and its device/inode/version is compared before
   use.
3. A target-changing transform retains its original authorization base and is
   reauthorized at the final opened target.
4. A privileged administrative input retains the startup trust mode and must
   be outside the later service account's mutation authority.

## Remediated findings

### FI-1: `SymLinksIfOwnerMatch` ordinary-component substitution

The owner-match walker first inspected an ordinary component with
`O_PATH|O_NOFOLLOW`, then reopened its name with usable flags. A concurrent
rename could make the owner/shape decision and returned descriptor refer to
different inodes.

The usable reopen now must match the pinned device and inode through the
verified `owner_component_reopen_admit` predicate. Directory descriptors are
retained for subsequent components, so a successful comparison cannot be
invalidated by a later directory-entry rename.

### FI-2: directory and cache consumers weakened owner-match policy

`DirectoryIndex`, autoindex metadata, and cache target discovery treated
`SymLinksIfOwnerMatch` as ordinary symlink following. That diverged from live
static dispatch: an owner-mismatched link could select an index, disclose
target type/size, or remain eligible for a cached representation even though
the live target was forbidden.

All three paths now consume the same descriptor-relative symlink-policy
resolver. A forbidden autoindex link remains name-visible for Apache
compatibility, but its target type and size are not disclosed.

### FI-3: filesystem rewrite lost its containment root

An admitted absolute rewrite target was later represented as
`target.parent()` plus `target.file_name()`. This discarded the document/alias
root that established containment. Replacing a writable content directory
between rewrite selection and dispatch could therefore make the second lookup
operate under a newly invented root.

`FilesystemTarget` now carries the original mapping root, the relative path
below it, and the selected descriptor path. Dispatch reuses the original root
and relative path. The verified `rewrite_filesystem_binding_admit` predicate
and rejection lemma make parent re-rooting an explicit forbidden transition.
Rewrite condition `-f`, `-d`, `-s`, and `-l` tests also use descriptor-relative
probes rather than canonicalize-then-stat.

### FI-4: expression file functions reconstructed authority from a pathname

Expression file tests, `file()`, and `filesize()` canonicalized a candidate
under the document root and then performed a later pathname metadata/open
operation. A rename after canonicalization could change the observed object;
these functions are reachable from access-file policy and may receive
request-derived operands.

The functions now keep only a validated relative operand and resolve it under
the document/alias-root descriptor. `file()` opens with nonblocking/no-follow
flags, enforces the 64 KiB regular-file limit, and checks the descriptor's
identity/version before and after the exact read. Escaping symlinks fail
closed for both content and metadata functions.

### FI-5: privileged proxy CA and RewriteMap program trust gaps

`SSLProxyCACertificateFile` used the no-symlink opener and a size/type check,
but did not retain the privileged generation's root-ownership policy or join
the administrative-input manifest. `RewriteMap prg` snapshotted and sealed its
helper correctly, but a root-started generation could initially snapshot a
service-owned executable.

Proxy CA reads now use the retained `AdminFileTrust` and enter the manifest.
Privileged RewriteMap helpers require a root-owned, non-group/other-writable
canonical executable and trusted parent tree before the sealed snapshot is
created. Root-controlled compatibility spellings such as `/bin -> /usr/bin`
remain supported: the configured spelling remains the runtime binding name,
while the canonical source is the manifest identity.

## Reviewed boundaries that did not require a change

- Static files and CGI already retain the opened object; CGI executes through
  its descriptor after target reauthorization.
- FastCGI retains the selected script descriptor, checks the lexical pathname
  against that inode immediately before sending parameters, and requires the
  configured stable-path policy because the external backend ultimately opens
  a pathname.
- Access files are parsed from stable descriptor snapshots and the resulting
  immutable layer is retained for the request.
- Authentication files use no-symlink service-immutable opens and revalidate
  cache hits against the inode.
- TLS certificate/key loading has the narrow, separately checked Certbot
  final-link exception; log/PID/OCSP/cache administrative paths use the
  descriptor-relative no-symlink administrative opener.
- Main and access-file `<IfFile>` are execute-on-read configuration
  conditions. Their filesystem observation is frozen while the configuration
  or access-file program is parsed, not repeated as a request-time pathname
  authorization decision.

## Residual trust boundaries

- The configured document/alias root and its parent deployment machinery are
  operator-controlled. Replacing that root is treated as an intentional site
  deployment change; content writers below the root do not gain that power.
- FastCGI/PHP receives a pathname rather than httpd-rs's descriptor. Safe use
  therefore still requires `HttpdRsFastCGIStablePath`; the explicit unstable
  capability accepts that external boundary.
- Kernel `openat2`, descriptor identity, procfs descriptor paths, filesystem
  ownership, and rename semantics are refinement assumptions below the Verus
  model.

## Evidence

- 15 filesystem unit tests, including component substitution, owner-mismatched
  `DirectoryIndex`, and autoindex metadata cases.
- 50 rewrite unit tests, including deterministic parent replacement after
  filesystem-target selection.
- 19 expression unit tests, including escaping-symlink content and size probes.
- Cache and privileged proxy-CA/RewriteMap regressions.
- Verus: 655 verified functions, 0 errors. New obligations cover ordinary
  owner-component reopen identity and retained rewrite-root binding.

