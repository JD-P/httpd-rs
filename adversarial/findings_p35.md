# Pass 35 — `.htaccess` comment continuation and PCRE2 auto-possessification divergences

- **Date:** 2026-11-09
- **Subject:** HEAD `3310fe390fae9552c4fc86c523ed69ea6d5a5d52`
  (`target/release/vapached`, rebuilt from the checked-out tree; no product
  source was edited).
- **Oracle:** Apache/2.4.69 (Debian), `mpm_event` + `mod_authz_core` +
  `mod_cgi` + `mod_mime`, loopback only.
- **Harnesses:**
  - `adversarial/p35/exploit_p35.py` — seven access-file cases; retained
    output `adversarial/p35/results_p35.txt`.
  - `adversarial/p35/pcre2_guard_p35.py` — five guarded-regex cases; retained
    output `adversarial/p35/results_p35_pcre2.txt`.
- **Method:** source audit of the access-file front end and the PCRE2
  compatibility translation, followed by live Apache-versus-vapached
  differentials over attacker-written `.htaccess` files and ACL guards.
- **Disposition:** **both confirmed and unfixed at HEAD.** P35-A is a
  fail-open configuration-parser differential; P35-B is a regex-engine
  match-semantics differential.

---

## 1. Executive summary

| # | Finding | Apache 2.4.69 | vapached at HEAD | Class |
|---|---------|---------------|------------------|-------|
| **P35-A** | Apache treats a trailing backslash as line continuation **before** comment handling, so `#\` swallows the next physical line. Vapache's `.htaccess` front end drops the comment line first and then parses the next line as an active directive. An attacker-written access file can therefore activate a grant Apache ignores, or can hide a handler section whose unmatched remainder makes Apache reject the whole file with `500`. | `#\` + `Require all granted` under a live `Require all denied`: `403`, no body. `#\` + `<Files "run.txt"> SetHandler cgi-script </Files>`: `500` for both the protected file and the script; no execution. | `200` with `P35-SECRET-CONTENT-9c41`; the hidden CGI executes and returns `P35-CGI-EXECUTED-9c41`. | authority bypass / protected read; hidden CGI execution where Apache rejects the access file |
| **P35-B** | The PCRE2 compatibility translation keeps greedy class repetitions backtrackable, while PCRE2 (Apache) auto-possessifies `\S*`/`\S+`/`\N+` before `\R`/`\v`. For a subject containing the obs-text NEL byte `0x85`, a negated guard that should deny becomes fail-open on vapache. | `!~ /\S*\v/` with `X-Test: A\x85B` → `403`; `!~ /\S*\R/`, `!~ /\N+\R/`, `!~ /\S+\R/` behave the same. | `200` for all four patterns; the same request is denied by Apache. | ACL guard bypass / regex parser differential |

P35-A is the stronger finding: the access file is attacker-written under the
project's established writable-`.htaccess` threat model, and the differential
turns a file Apache treats as inert (or rejects outright) into active policy.
P35-B is narrower: it requires an unusual negated guard that places a greedy
`\S`/`\N` repetition immediately before `\R`/`\v`, plus an obs-text NEL byte in
the guarded value.

---

## 2. P35-A — comment continuation is applied after comment dropping

### 2.1 Root cause

`.htaccess` files are read by `config_frontend::logical_lines()`
(`crates/server/src/config_frontend.rs:51`, imported at
`crates/server/src/htaccess.rs:14`, called at `htaccess.rs:1069`). That
function removes comments before it considers continuations:

```rust
for raw in text.lines() {
    let line = raw.trim_end_matches('\r');
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        continue;                     // comment dropped here
    }
    ...
    let continuation = line.ends_with('\\');
    if continuation {
        cur.push_str(&line[..line.len() - 1]);
    } else {
        cur.push_str(line);
        out.push(std::mem::take(&mut cur));
    }
}
```

Apache assembles continued lines first (`ap_cfg_getline` removes the
backslash/newline and appends the next line) and only then decides whether the
assembled line is a comment. A physical line ending in `\` therefore continues
a comment: the next line is part of the comment and is never parsed as a
directive. Vapache has already discarded the comment, so the next line is
parsed normally.

The main-configuration path uses `logical_lines_with_numbers()`, which *does*
join the continued line before the compiler examines it; the live control
below confirms the defect is specific to the `.htaccess` front end.

### 2.2 Exploit A — activate a grant Apache comments out

Main configuration:

```apache
<Directory "/srv/app/www/sub">
    AllowOverride AuthConfig
    Require all denied
</Directory>
```

Attacker `.htaccess`:

```apache
#\
Require all granted
```

Apache: the `#\` comment continues into the `Require` line, so the parent
`Require all denied` remains live (`403`). Vapache: the comment is dropped and
`Require all granted` is active (`200`, protected body).

Live output (`adversarial/p35/results_p35.txt`):

```text
## A-hidden-grant
   /sub/file.txt  apache=403 vapache=200 apache_leak=False vapache_leak=True
## A-control-plain-grant
   /sub/file.txt  apache=200 vapache=200 apache_leak=True vapache_leak=True
## A-control-comment-no-continuation
   /sub/file.txt  apache=200 vapache=200 apache_leak=True vapache_leak=True
## A-chained-hidden-grant
   /sub/file.txt  apache=403 vapache=200 apache_leak=False vapache_leak=True
```

Controls pin the mechanism: without the trailing backslash Apache also sees
the grant (`A-control-comment-no-continuation`, `200/200`), and a plain grant
is permitted by both (`A-control-plain-grant`). Chaining `#\` lines hides
several physical lines from Apache while vapache still activates the final
directive (`A-chained-hidden-grant`).

### 2.3 Exploit B — hidden handler section executes where Apache rejects the file

With `AllowOverride FileInfo` and `Options +ExecCGI` in the directory, the
attacker writes:

```apache
#\
<Files "run.txt">
SetHandler cgi-script
</Files>
```

Apache: the first comment continues into the `<Files>` line, so the
`SetHandler` line is active at top level and the later `</Files>` is an
unmatched close. Apache rejects every request in that directory with `500`;
the CGI never runs. Vapache: the hidden `<Files>` section is active, the
uploaded `run.txt` is classified as `cgi-script`, and the CGI executes as
`www-data`.

Live output:

```text
## B-hidden-cgi
   /sub/file.txt  apache=500 vapache=200 apache_leak=False vapache_leak=True
   /sub/run.txt   apache=500 vapache=200 apache_exec=False vapache_exec=True
## B-control-plain-cgi
   /sub/file.txt  apache=200 vapache=200 apache_leak=True vapache_leak=True
   /sub/run.txt   apache=200 vapache=200 apache_exec=True vapache_exec=True
```

The plain control shows that the handler override itself is permitted by the
tested `AllowOverride FileInfo`/`Options +ExecCGI` posture; the differential is
that Apache's parser rejects the *written* access file while vapache silently
activates the hidden section. This is the same class as P18-A: an access file
Apache refuses is accepted and executed by vapache.

### 2.4 Main-configuration control

The same `#\` + `Require all granted` text embedded inside the main
`<Directory>` block gives `403` on both servers (case
`C-hidden-grant-in-main-config`), confirming that
`logical_lines_with_numbers()` already handles comment continuation correctly
and the fix belongs in the `.htaccess` line assembler.

### 2.5 Preconditions and blast radius

- Attacker can write an access file in a served directory. This is the
  established threat model of P14-A, F60-D, P18-A and P33/P34: an upload,
  avatar, cache, or application-writable directory with `AllowOverride`
  enabled and `VapacheCapability AccessFiles On`.
- Case A needs `AllowOverride` to permit `Require` (for example
  `AllowOverride AuthConfig` or `All`). Case B needs the handler directive's
  category (`FileInfo`) and the directory's `Options +ExecCGI`.
- **Blast radius:** the hidden directive can be any access-file policy:
  `Require`, `<Files>` handlers, `RewriteRule`, `Header`, `Options`,
  `DirectoryIndex`, `ErrorDocument`, MIME/handler directives, etc. The
  attacker can make vapache enforce a different policy than the file's Apache
  meaning, and can make Apache-invalid access files executable.
- **Attacker cost:** one uploaded file. No body, no credential, and no
  configuration write beyond the access file.

### 2.6 Relationship to prior passes

- **P14-A / P18-A** established that the writable-`.htaccess` boundary is a
  security boundary and that accepting an access file Apache rejects is a
  code-execution class. P35-A is a new front-end parser differential that
  bypasses the same boundary without relying on section-order or
  `AllowOverrideList` semantics.
- **P24** hardened expression parsing; **P23** hardened PCRE2 translation.
  Neither pass covered the line assembler’s comment/continuation ordering.
- The project’s `logical_lines_skip_htaccess_comments` unit test
  (`config_frontend.rs:336`) asserts the current behavior but has no Apache
  differential for a comment ending in `\`.

---

## 3. P35-B — PCRE2 auto-possessification over-matches on NEL

### 3.1 Root cause

The compatibility engine translates a PCRE2 pattern into a non-backtracking
automata pattern. For `\S*`/`\S+`/`\N+` immediately followed by `\R` or `\v`,
PCRE2's optimiser auto-possessifies the repetition; the same accepted pattern
then fails to match a subject where the repeated class and the line-break atom
overlap on the NEL byte `0x85`. Vapache's translation keeps the repetition
backtrackable, so it finds a match.

The existing `validate_line_constructs()` already special-cases
`\N*?\R` as a “PCRE2 auto-possessified line sequence”
(`crates/pcre2/src/lib.rs:1435`), but the greedy/`+`/`\S`/`\v` siblings are not
covered.

### 3.2 Live evidence

Configuration:

```apache
<Directory "/srv/app/www">
    Require all granted
    <If "%{HTTP:X-Test} !~ /\S*\v/">
        Require all denied
    </If>
</Directory>
```

The `!~` guard denies values that do **not** contain the pattern. On Apache the
pattern does not match `A\x85B`, so `!~` is true and the request is denied; on
vapache the pattern matches, so `!~` is false and the request is allowed.

Live output (`adversarial/p35/results_p35_pcre2.txt`):

```text
## S-star-v  pattern=\S*\v
   plain apache=403 vapache=403
   nel   apache=403 vapache=200
## S-star-R  pattern=\S*\R
   plain apache=403 vapache=403
   nel   apache=403 vapache=200
## N-plus-R  pattern=\N+\R
   plain apache=403 vapache=403
   nel   apache=403 vapache=200
## S-plus-R  pattern=\S+\R
   plain apache=403 vapache=403
   nel   apache=403 vapache=200
## plain-v-control  pattern=\v
   plain apache=403 vapache=403
   nel   apache=200 vapache=200
```

The plain-value controls agree (`403/403`), and the simple `\v` control agrees
on NEL (`200/200`), isolating the difference to the greedy-class/`\R`/`\v`
translation.

The crate-level fuzzer found additional shapes (`.*\R`, `.+?\R`,
`^.{0,1}\R`, `^\S*\v$` and others) that did **not** reproduce against the
installed Apache 2.4.69; they are recorded as negative observations rather
than claims. The four patterns above were all reproduced live.

### 3.3 Preconditions and blast radius

- The operator must use a **negated** regex guard (`!~`, `Require env` with a
  negated expression, or an equivalent `!` rewrite condition) whose pattern
  places a greedy `\S`/`\N` repetition immediately before `\R`/`\v`.
- The guarded subject must contain `0x85` (NEL), which is permitted as
  obs-text in HTTP header values and can be carried in a request header.
- The guard is an access-control rule; the demonstrated result is that Apache
  denies and vapache allows. No authentication or body is required.
- Because the pattern shape and the `!~` polarity are both needed, this is a
  medium-impact, narrow-precondition finding rather than a general bypass.

### 3.4 Relationship to prior passes

P23/P24 built the PCRE2 differential fuzzer and fixed the counted-repetition,
character-class and final-newline families. This is a remaining
auto-possessification shape in the same translation. P16-B fixed Unicode-class
semantics but not the `\S`/`\N` plus `\R`/`\v` match-truth difference.

---

## 4. Remediation direction (not applied in this pass)

1. **P35-A:** assemble physical lines exactly as Apache does *before* deciding
   whether a logical line is a comment. Either use
   `logical_lines_with_numbers()` and drop comment logical lines afterwards,
   or add a continuation-aware comment skip to `logical_lines()`. Add a
   regression with `#\` + `Require all granted`, a chained `#\` grant, a
   hidden `<Files>` handler, and the main-config control.
2. **P35-B:** extend `validate_line_constructs()` (or the translation itself)
   to cover every greedy class repetition immediately before `\R`/`\v`/`\h`
   that PCRE2 can auto-possessify (`\S*`, `\S+`, `\N*`, `\N+`, and the same
   shapes inside groups/alternations), or reproduce PCRE2's match semantics.
   Keep the simple `\v`/`\R` forms working; they agree with Apache.

---

## 5. Negative observations and controls

- **P35-O1:** The crate-level PCRE2 oracle found `.*\R`, `.+?\R`,
  `^.{0,1}\R`, `^\S*\v$` and `^\S+\h$` match differences that did not
  reproduce against the installed Apache 2.4.69. They are not claimed as
  vulnerabilities; the live harness records only the four confirmed patterns.
- **P35-O2:** The same `#\` continuation text in the **main** configuration is
  swallowed like Apache on both servers (`C-hidden-grant-in-main-config`,
  `403/403`), so the fix is scoped to the `.htaccess` line assembler.
- **P35-O3:** A three-million-iteration randomized sweep of the exported
  OCSP, TLS-policy, CGI-response, FastCGI-record, proxy-response,
  WebSocket-negotiation, HTTP/2-frame and cache-metadata fuzz entry points
  found no panic or abort.
- **P35-O4:** The simple `\v` guard control matches NEL on both servers; the
  P35-B divergence needs the greedy repetition before the line-break atom.

---

## 6. Retained files

- `adversarial/p35/exploit_p35.py` — seven-case Apache/vapached access-file
  differential; exits non-zero if either P35-A divergence disappears.
- `adversarial/p35/results_p35.txt` — retained HEAD run output.
- `adversarial/p35/pcre2_guard_p35.py` — five-case guarded-regex differential.
- `adversarial/p35/results_p35_pcre2.txt` — retained HEAD run output.
- `/tmp/opencode/p35-harness/` and `/tmp/opencode/p35-pcre2-harness/` — full
  per-case configs, fixtures and logs when `--keep` is used.