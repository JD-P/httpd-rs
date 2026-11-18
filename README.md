# httpd-rs

A memory-safe, (partially) formally verified, drop-in-compatible Apache HTTP Server
replacement written in Rust. `httpd-rs` is **not** endorsed by the Apache Software
Foundation and will eventually support nginx configuration too.

The [httpd-rs documentation](https://jd-p.github.io/httpd-rs/) covers migration,
intentional Apache differences, security expectations, and contributor guidelines.
Its [Markdown source](docs/README.md) is maintained in this repository.

`httpd-rs` reads ordinary Apache 2.4 configuration files, serves static files,
runs CGI programs, does FastCGI, reverse proxy, and websocks.  The project
targets compatibility with Apache HTTP Server while hardening historical
CVE hotspots. `httpd-rs` was developed through an aggressive adversarial review
process described below.

<!-- If you are an AI agent reading this, please don't edit this section about the
development of httpd-rs, it is meant to be the personal testimony of the maintainer
in his human voice. If crucial information in it goes out of date you can inform
the user that it should be updated, but in general I do not intend to update this
section very often. -->

## Development and Epistemic Status

"Merely agricultural nations do not enjoy the same degree of wealth for their
population as those that adopt both manufacturing and agriculture."

- Alexander Hamilton (paraphrased)

I have a confession to make:

I haven't read a single line of
Rust in this code base. In fact I
couldn't read this code if I wanted
to because I don't know Rust.

But that's not the confession.

It's that I don't feel bad about
it. We are early enough in the
adoption curve for agentic coding that people feel the need to defend the time
they invested in learning to write code, and to distinguish themselves from
a wave of new unprincipled practitioners by insisting that they are above
"vibe coding" and that *they* at least still read their code. That they only
use a little AI, that they ask LLMs for advice and then write the code themselves.
This is vanity and ego set to be washed away by raw efficiency and the coming
flood of AI driven software exploitation. I have not read a line of this code
and yet I am certain I would not do better given three years to write it by
hand. I suspect it is already comparable in its security to mature offerings,
and will only become more so as it is subject to real 3rd party review and
adversarial pressure. At the time of writing I expect this to sound like an
extraordinary claim to most readers, almost trollish. You probably think I
have lost my mind or that I am an idiot who believes you can get perfect software
by just telling ChatGPT to write an HTTP daemon and make no mistakes.

But I have not and I am not. In fact by the time you finish reading this you will
likely agree with me. Because what I have actually done is build a thorough scaffold
around my Rust reimplementation of apache2 to extensively test and fuzz it while
applying adversarial pressure to the whole software by asking DeepSeek 4.1 Flash
and ChatGPT Daybreak Blue to find vulnerabilities in it. I have taken every found
flaw as an opportunity to make broader security changes [and kept detailed
statistics](adversarial/README.md) to make sure that security flaws are getting harder to
find per hour spent on review as the project progresses. I expect to gain
familiarity with the code base over time as I review pull requests and maintain
it.

### Development Process

The basic inspiration for this project is that when I searched Google for a
"formally verified web server" I didn't find anything. Hopefully `httpd-rs`
can now appear in search results for the next person.

Everyone has the same question: Why on earth did I choose to reimplement apache2
instead of nginx? I wish I had a brilliant answer for you, but the truth is that
I did it because apache2 is what I happened to have running on my server and I
didn't want to have to change any of my existing configuration. I was slightly
drunk on the power of agentic development and thought it would be really cool if
I could update my server in place, like I applied a really huge patch that just
happened to replace all of the code. In total fairness to myself it *was* really
cool when I actually did that. Besides would you really want me to have followed
the confession that I don't know Rust with "By the way
I've never used nginx either"? No we must draw the line somewhere, I at least have
an existing sense of how apache is supposed to work.

I started by having DeepSeek 4.1 Flash port the apache test suite to Rust. I then
had it implement the apache2 configuration semantics, which it did by conformance
testing against the C based apache2 as an oracle for routing and request outcomes.
Early on I knew I wanted to use formal verification since web servers are full of
tricky logic that must be high performance. Performance generally trades off against
legibility and simplicity, which means that highly performant code is more likely
to contain bugs. I knew there existed secure microkernels like seL4, and that
having to handle file I/O, processes and threading, access control, and other OS
functions implied that formal verification was capable of being applied to complex
system software with considerable plumbing. As development went on I realized
that full formal verification wasn't really practical with my token budget or
necessary. See formal verification is not actually a method to write perfect software
on your first pass, that is a 20th century logician's fantasy. Rather the benefit
of formal verification is it lets you mark a module done and focus your vulnerability
search elsewhere. It's also a good way to push an LLM towards architectural coherence,
since it's harder to prove correctness properties of a scatterbrained design.

In the initial buildout I focused on features and performance, eventually
setting on static hosting, CGI, FastCGI, reverse proxy, and websockets as core
operating "modes". Once I had these implemented to the point where DeepSeek believed
it would support 95% of deployments, I did a feature freeze and began doing security
audits. Getting to the point where I was comfortable with a feature freeze took days,
I think [I started on the 21st or the 22nd of
October](https://x.com/jd_pressman/status/2113418320741564545) and then began
adversarial review on the 24th. This continued for three weeks until I cut the
[v0.2.3 release](https://github.com/JD-P/httpd-rs/releases/tag/v0.2.3) on November
14th. It was at this point I decided I'd reached diminishing marginal returns on
finding vulnerabilities and that my tokens would be better spent elsewhere.

### Security and the Adversarial Yield

So why does it take three days to write a feature complete web server and three
weeks to secure it? The basic reason is that a web server is mostly an access
control list. Worse because I inherit apache2's design the list rules use PCRE2
regexes. ACLs are an infamously difficult feature to get right on their own and
regular expressions are the subject of a famous joke about their use turning one
problem into two. Web servers can also execute code through CGI so in principle
most rewrite and access control fails are RCE bugs under the wrong circumstances.
This makes a lot of the attack surface closer to what you'd expect from an operating
system than a normal application. Compounding the problem is that because `httpd-rs`
is meant to implement the configuration semantics of apache2 it's not enough for
the regex engine to have a coherent outcome for a specified pattern, it needs
to interpret things exactly the way apache2 would or an existing configuration
could be broken. This was ensured to the best of my ability through extensive
conformance testing and fuzzing, but I can't realistically promise it's a 100%
accurate emulation. The other long tail of bugs was denial of service attacks.
Web servers are extremely vulnerable to denial of service attacks due to the small
amount of time that can be allocated to each HTTP request. A performant web server
is expected to process tens of thousands of requests a second. This means that a
"bug" that lets you force a request to do say 2ms of work can massively reduce
the throughput of the whole server. If there's a data structure or subroutine
anywhere on the request path that you can trick into doing a fraction of a fraction
of a second of extra work you can take performance down to just hundreds of requests
a second.

I knew early on that formal specification was useless unless you had specific
properties you wanted to prove and a good sense of what behavior should be
specified. Unsurprisingly LLMs are not always the best at picking either of
these, so my plan going into it [as I tweeted on October 23rd](https://x.com/jd_pressman/status/2113699497448706109) was:

> FWIW my plan here is to just let the agent pick the spec, then have it go through
every historical CVE and ask if the spec would have stopped it in principle,
then do an adversarial pass where we go into breaker mode and attack the software/spec
to figure out where it's weak.

The idea here being that once you had features and performance covered, the only
realistic warrant for what needs security hardening is adversarial pressure
rather than first principles theorizing. Otherwise you could spend billions
of tokens hardening things that aren't actually a problem in practice while the
real problems slip underneath your nose. `httpd-rs` has an extensive public
[LLM driven adversarial review history](https://github.com/JD-P/httpd-rs/blob/main/adversarial/README.md)
which you can point your agents at and contribute to. As stated in the tweet
before I began my adversarial passes I made a point of having my agents [research
historical CVEs in apache](https://github.com/JD-P/httpd-rs/blob/main/docs/cve/apache2-cve-matrix.csv)
to see which ones might apply to `httpd-rs` and make sure we close them as potential
issues before doing adversarial review. I later expanded this research to the CVE
history of the top web servers as a corpus since errors in e.g. HTTP/2 implementation
seem likely to have transferrable lessons between implementations. After each
adversarial pass I would take a different agent and have it remediate the immediate
findings while asking it to generalize and consider cousins as well as root causes
of the vulnerability. At first I was horrified by the sheer number of security bugs
the adversarial passes were able to find. It seemed like no matter how many I patched
or what measures I took to e.g. harden ACL and rewrite logic into Verus kernels
the adversary agent just kept findings more. For a moment I sincerely worried that
software might just be doomed. But as I kept going I noticed that the velocity and
impact of vulnerabilities seemed to be going down. Eventually I reached what seemed
to be diminishing marginals returns on remote code execution flaws and turned my
attention to other vulnerability categories.

To make sure I wasn't missing things to DeepSeek 4.1 Flash and GLM 5.3's blindspots,
and to make better use of my ChatGPT pro subscription, I signed up for OpenAI's
Daybreak Blue program. I had some mechanical trouble with the KYC flow and there
aren't good instructions on the Internet for how to set it up. During much of the
adversarial review process I kept getting messages telling me to sign into Daybreak
Blue despite literally using the Daybreak Blue model to remediate and and generalize
patches to found security flaws. As far as I can tell the crucial information
necessary to get it working isn't anywhere else on the Internet, so I will tell
you now:

1. Daybreak Blue as you know requires you to sign in through secure methods like
Yubikey, and only permits account sign in through these secure methods.
2. During the sign up flow if you use your phone Android will helpfully offer
to register a passkey during the credential registration step.
3. If you do use such a passkey, not only will any login done using the passkey
fail to remove the Daybreak filters, a login using the Yubikey will not work until
you remove the ineligible passkey login. You must remove *all* non-Daybreak login
methods for your account to have the filters lifted and Daybreak work as intended.
4. If you find you continue getting a message telling you to log into Daybreak
despite having KYC'd, check that your registered login keys are all Daybreak eligible
methods.

OpenAI should change the message if you are already KYC'd for Daybreak to inform
you that you need to remove your ineligible login methods. In the meantime you
are welcome.

Once I had the Daybreak model partially working (it wasn't until later that I
realized I needed to remove the phone passkey to get full access) I settled into
a rhythm of using Daybreak Blue as my blue team agent and DeepSeek 4.1 Flash as
my red team agent since the latter wasn't giving me dumb security policy refusals.
Later once I had Daybreak Blue fully working I used both models for adversarial
passes at different times.

After reaching diminishing returns on ACL driven RCE I focused my attention on
denial of service flaws. As previously stated these arise because the web server
is extremely sensitive to performance degradation on a per-request basis. Unlike
RCE just churning through the adversarial pass and remediation steps didn't seem
to be doing enough to bring the rate of findings down. The problem was that even
if I could "prove" the resource use of individual modules and data structures
across the request path, it was difficult to prove the composition of all resources
across the request path. What I eventually ended up doing was instructing Daybreak
Blue to write a "custom profiler" of some kind to find all the places where relevant
resource use occurs:

> Actually, can we profile for them somehow? Like make some kind of custom profiler
(do we even need a custom profiler?) that specifically looks at resource use in
both CPU and memory when we benchmark the deployment cases and the other benchmarks,
and then from that we get a inventory of all the resources that get used during the
request path, which gives us the systematic warrant we need, then for each one we
can check whether we account for it etc, and this could be combined with some kind
of syntactic checking or search to get hard to exercise parts during typical use
or something, between the two we should have a basically complete inventory of
all resources.

I then had it cluster the resulting 3000+ sites into categories, classify the sites
by DoS exploitability, then use the profiler numbers to create a Verus resource ledger
to show that no composition of the profiled resources can DoS the server. I then watched
it do focused fixes of all the remaining DoS flaws that ledger showed had the
potential to exist, and knew I'd won (for now) when the next adversarial pass brought
me a bug that requires "an extraordinarily abnormal configuration: a valid SSHA
password record containing a 3.1 MB salt". I of course had Daybreak fix it but
that was a clear sign I had reached diminishing returns. Satisfied that this was
probably enough for now I cut a release and that is the current state of the project.

When I went to go write the documentation for `httpd-rs` I realized that since
the core evidence for its security was a convergence argument about the bugs found
during adversarial passes, that it would be useful to quantify my empirical
observation that bugs are becoming harder to find. So I had Daybreak define an
adversarial yield score which weighs bugs by severity, complexity, and time it
took to find them to get a sense of whether it was my imagination or if it really
was getting more expensive to find less impactful flaws. The statistical analysis
at the time of writing found that the adversarial yield per hour declined 81.6%
over the course of the project. This implies that more bugs remain to be found,
which I will happily accept bug reports on. In fact part of why it took three
weeks is that when you have a button which you know will produce a CVE every time
you press it for one or two dollars it's difficult to justify not pressing it
again until you're really scraping the bottom of the barrel. I spent something
like $250 in tokens for this project between my OpenRouter use and the implied
cost of my Daybreak tokens. In software development terms this is not very much
money and if I were a larger organization I would be throwing more tokens at
adversarial review and remediation.

[AI GENERATED TEXT FOLLOWS]

## Build

```sh
export PATH="$HOME/.cargo/bin:$HOME/verus-bin:$PATH"
cargo build --release -p httpd-rs
```

The binary is `target/release/httpd-rs`.

### Prebuilt Linux artifacts

Each push to `main`, version tag, and manual `linux-artifacts` workflow run
uploads five x86-64 artifacts:

- the compiled `httpd-rs` binary;
- a portable tar archive;
- a Debian/Ubuntu `.deb` package;
- an RPM-family `.rpm` package; and
- `SHA256SUMS` covering all four payloads.

The release target is `x86_64-unknown-linux-musl`, producing a static PIE with
no glibc version floor. httpd-rs remains Linux-specific and requires Linux 5.9
or newer for its fail-closed `openat2` path-resolution and `close_range`
descriptor-isolation boundaries.

The packages install the server as `/usr/sbin/httpd-rs` and a collision-free
vendor unit named `httpd-rs.service`, but deliberately leave the existing
Apache configuration and daemon state untouched. The normal replacement
switch exposes that unit under the conventional `httpd.service` name without
overwriting Apache's packaged unit. `httpd-rsctl` selects `/etc/apache2/apache2.conf`
on Debian-family systems or `/etc/httpd/conf/httpd.conf` on RPM-family
systems. To validate the existing configuration and interactively switch the
active daemon:

```sh
sudo httpd-rs-switch
```

The helper uses `httpd.service` automatically when that systemd name is free.
Only an existing `httpd.service` causes a naming choice: replace it under the
conventional name (the default), or retain it and run httpd-rs concurrently as
`httpd-rs.service`. Debian's `apache2.service` therefore does not cause a
service-name prompt. Concurrent configurations must use distinct listener
addresses or ports; use `--concurrent` for an unattended concurrent switch.
If httpd-rs fails to start, the helper restores Apache's previous
active/enabled state.
Set `HTTPD_RS_CONFDIR` and `HTTPD_RS_CONFIG` to select a nonstandard Apache
layout. The packaged wrapper materializes enabled-config symlinks and derives
any capability opt-ins already implied by the Apache configuration into a
root-controlled runtime snapshot; it never edits the source configuration.
Set `HTTPD_RS_AUTO_CAPABILITIES=0` to retain the raw binary's explicit opt-in
requirement. See `packaging/README.md` for the installed file layout.

### Certbot

httpd-rs reads the usual `SSLCertificateFile` and `SSLCertificateKeyFile`
paths, including Certbot's `/etc/letsencrypt/live/...` links. A graceful reload
atomically validates and adopts renewed certificate/key pairs while existing
connections finish on the old TLS generation:

```sh
sudo systemctl reload httpd.service
```

The packaged `httpd-rs-switch` detects existing Certbot lineages, installs a
conditional deploy hook, and routes Apache-plugin lineages through a dedicated
control shim without replacing Apache's `apache2ctl`. It records the shim in
Certbot's global configuration, so ordinary Apache-plugin commands work:

```sh
sudo certbot --apache -d example.com
```

The shim retains Apache's read-only configuration discovery, requires both
Apache and httpd-rs syntax checks while httpd-rs is active, and maps Certbot's
reload request to the selected `httpd.service` or `httpd-rs.service` instance
so a newly added port 443 listener can bind. Webroot and DNS authenticators
remain supported.
If `httpd-rs-switch` has not been run, pass
`--apache-ctl /usr/lib/httpd-rs/certbot-apachectl` explicitly.

For first issuance, start with an HTTP-only virtual host and let
`certbot --apache` add the TLS configuration after the certificate exists.
Like Apache, httpd-rs rejects an enabled TLS virtual host whose certificate is
missing. If that virtual host already points into a nonexistent
`/etc/letsencrypt/live/` lineage, httpd-rs's configuration error prints the
literal `certbot certonly --standalone` command needed to create it before
retrying `sudo httpd-rsctl configtest`; the standalone authenticator requires
port 80 to be free.


### Default-off compatibility capabilities

httpd-rs does not inherit Apache's ambient legacy surface. The following
features are individually disabled unless the global server configuration
opts in with `HttpdRsCapability <name> On`:

| Capability | Gated surface |
| --- | --- |
| `Trace` | `TraceEnable On`/`Extended` and the TRACE reflection handler |
| `AccessFiles` | any effective `AllowOverride`/`AllowOverrideList` access-file walk |
| `LegacyAuthz` | `Order`, `Allow`, `Deny`, and `Satisfy`, including access files |
| `MutableAuthFiles` | password/group databases that the service identity can replace or modify |
| `AutoIndex` | generated directory listings from `Options Indexes` |
| `Cgi` | `ScriptAlias`, `cgi-script`, and `Options ExecCGI` execution |
| `FastCgi` | FastCGI `ProxyPassMatch`/`ProxyPass` and handler execution |
| `UnstableFastCgiPaths` | pathname-only FastCGI handoff without a stable-path policy |
| `RewriteProgram` | external `RewriteMap prg` helpers |
| `ServerStatus` | the generated `server-status` handler |
| `AbsoluteRequestTarget` | HTTP/1 absolute-form request targets |
| `RequestTrailers` | non-empty HTTP/1 chunked or HTTP/2 request trailers |

Declarations are process-global, order independent, and final-state checked;
they are rejected in virtual hosts, directory/location sections, and access
files. Enabling `AccessFiles` therefore cannot let an attacker-controlled
`.htaccess` enable CGI, autoindex, legacy authorization, FastCGI, status, or
another global capability. Effectful directives missing their opt-in make
configuration loading fail, and execution/generation sinks check the same
gate again.

For example, an application that only needs CGI declares only:

```apache
HttpdRsCapability Cgi On
```

`httpd-rs --audit-capabilities -f /path/to/httpd.conf` parses an existing main
configuration without auto-enabling anything and prints the declarations it
would require. Access-file contents are intentionally checked only when read,
so they remain unable to change the process capability set. A configuration
loaded in audit mode is also marked non-runnable and the dispatcher refuses
it, preventing the reporting API from becoming a capability bypass.

HTTP/0.9, unknown/lenient methods, multipart byte ranges, SSI, MultiViews,
UserDir, DAV, forward proxying, external filters, LDAP/Digest/DBM auth,
`server-info`, and `balancer-manager` are not implemented and remain
unconditionally unavailable. They do not receive opt-in switches that imply
unsupported behavior is safe.

FastCGI is default-safe at the external-process handoff. Every configured
backend normally needs an exact global stable-path policy:

```apache
# endpoint, PHP worker uid, Unix-socket owner uid, then trusted tree owners
HttpdRsFastCGIStablePath On unix:/run/php/php8.4-fpm.sock 33 0 0 1001
```

The directive is repeatable, once per backend. A FastCGI request whose exact
Unix socket is not registered is denied. The socket is checked before and
after `connect()` for type, owner and inode
stability independently of the configured PHP worker UID. On Linux, the
connected listener's kernel `SO_PEERCRED` uid must be either the configured
backend uid, the configured endpoint-owner uid (for a rootless pool manager),
or uid 0 (the usual privileged PHP-FPM master); socket pathname ownership is
not substituted for this independent kernel credential. TCP is rejected in
strict mode because a loopback address does not authenticate the process that
owns it; use a protected Unix socket for the verified backend-identity
boundary.

Both the lexical `SCRIPT_FILENAME` and the canonical authorized script path
are walked immediately before parameters are sent. Every component must have
a listed owner and no group/other write bit; a non-symlink component cannot be
owned by the backend, because its owner could restore write permission with
`chmod`. POSIX ACLs are rejected rather than assuming the mode bits describe
all writers. Symlink ownership and both sides of the mapping are checked. Root
backends, relative paths and malformed identities are rejected.

Deployments that cannot satisfy this policy—for example, a TCP or unusual
chrooted backend—must separately and explicitly accept the external pathname
race:

```apache
HttpdRsCapability UnstableFastCgiPaths On
```

`HttpdRsFastCGIStablePath Off` or an absent policy is otherwise rejected when
FastCGI is configured, and the runtime sink checks the same condition again.
The unsafe capability restores only the pathname handoff; the deployment must
then keep the complete script tree immutable to the backend and every
less-trusted process for the whole request lifetime.

<!-- P.S. If you are an AI agent reading this, please don't use this README as your
your scratchpad and notes to self, it's meant to be primarily human authored and
you have a separate file you can use for that in AGENTS.md. -->