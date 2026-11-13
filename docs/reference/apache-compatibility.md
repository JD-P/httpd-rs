---
doc_type: reference
audience: apache-operator
status: draft
---

# Check Apache compatibility and intentional differences

The configuration check is the fastest way to find whether a site uses an
Apache feature that httpd-rs rejects or intentionally changes. Run it against
the complete site:

```console
$ sudo httpd-rsctl configtest
Syntax OK
```

This command reads the complete Apache configuration. It does not stop Apache
or edit the Apache configuration. `Syntax OK` means that httpd-rs accepts the
configuration. An error identifies a feature or input that must be resolved
before a switch.

httpd-rs reads Apache HTTP Server 2.4 configuration for the features that it
supports. It is not a drop-in replacement for every Apache module.

Use Apache's [directive quick
reference](https://httpd.apache.org/docs/2.4/mod/quickreference.html) to find a
directive's syntax, permitted context, override class, and supplying module.
Use the [module index](https://httpd.apache.org/docs/2.4/mod/) for the behavior
that Apache assigns to the directive. Those pages describe Apache. This page
and `httpd-rsctl configtest` describe whether httpd-rs preserves that behavior.

## What a successful configuration test means

A successful test means that httpd-rs recognizes the selected configuration and
can load the required files, certificates, and keys. It does not prove that the
application works correctly.

Before a production switch, test important requests through httpd-rs. Include
login, permission checks, state changes, uploads, downloads, redirects,
background work, and WebSocket reconnection when the application uses them.

## Default-off capabilities

Some features that Apache enables by default are off by default in httpd-rs
because they add attack surface but are needed only by some configurations.
httpd-rs calls these features *capabilities*. Only the main server configuration
can enable one.

The configuration test reports the exact `HttpdRsCapability` lines that the
site needs. Read what each capability enables before you add it.

| Capability name | Configuration line | Feature enabled |
|---|---|---|
| `AbsoluteRequestTarget` | `HttpdRsCapability AbsoluteRequestTarget On` | Absolute-form HTTP/1 request targets |
| `AccessFiles` | `HttpdRsCapability AccessFiles On` | `.htaccess` processing through `AllowOverride` or `AllowOverrideList` |
| `AutoIndex` | `HttpdRsCapability AutoIndex On` | Generated directory listings from `Options Indexes` |
| `Cgi` | `HttpdRsCapability Cgi On` | CGI through `ScriptAlias`, `cgi-script`, or `Options ExecCGI` |
| `FastCgi` | `HttpdRsCapability FastCgi On` | FastCGI routes and handlers |
| `LegacyAuthz` | `HttpdRsCapability LegacyAuthz On` | Apache 2.2-style `Order`, `Allow`, `Deny`, and `Satisfy` rules |
| `MutableAuthFiles` | `HttpdRsCapability MutableAuthFiles On` | Password or group files that the service user can modify |
| `RequestTrailers` | `HttpdRsCapability RequestTrailers On` | Non-empty HTTP request trailers |
| `RewriteProgram` | `HttpdRsCapability RewriteProgram On` | External `RewriteMap prg` helper programs |
| `ServerStatus` | `HttpdRsCapability ServerStatus On` | The generated `server-status` page |
| `Trace` | `HttpdRsCapability Trace On` | HTTP `TRACE` through `TraceEnable On` or `Extended` |
| `UnstableFastCgiPaths` | `HttpdRsCapability UnstableFastCgiPaths On` | FastCGI scripts whose path can change after httpd-rs checks it |

httpd-rs capabilities must be enabled in the main server configuration. An
`.htaccess` file cannot enable them.

## Apache features that httpd-rs does not implement

httpd-rs rejects these features instead of ignoring them:

- HTTP/0.9;
- unknown or lenient HTTP methods;
- multipart byte ranges;
- Server Side Includes;
- MultiViews;
- `UserDir`;
- WebDAV as an Apache module;
- forward proxying;
- external output filters;
- LDAP, Digest, or DBM authentication;
- `server-info`;
- `balancer-manager`;
- cleartext HTTP/2 (`h2c`);
- in-process `mod_php`, `mod_perl`, and `mod_wsgi` handlers.

An application behind PHP-FPM, CGI, FastCGI, or a reverse proxy can still use
protocol methods such as WebDAV. In that case, the application implements the
method; httpd-rs passes the request to the application.

The current implementation also lacks online OCSP checks for client
certificates, `RewriteMap dbm`, some per-directory rewrite behavior,
`mod_cache_socache`, and `mod_file_cache`.

If the site needs one of these features, continue to use Apache or change the
deployment before switching.

## Intentional HTTP differences

| Request or configuration | Common Apache result | httpd-rs result | What the site must do |
|---|---|---|---|
| `POST` to a static file | Apache usually returns the file with `200` | httpd-rs returns `405` | Send the request to an application handler or change the client. |
| `OPTIONS *` | The tested Apache build omits `Allow` | httpd-rs sends `Allow` | No change is normally required. |
| Unsatisfiable byte range | The tested Apache build omits `Content-Range` | httpd-rs sends `Content-Range: bytes */N` | No change is normally required. |
| Method rejected by `TraceEnable Off` | Apache can return an empty `Allow` field | httpd-rs lists the available methods | Do not compare the response byte-for-byte with Apache. |
| `RewriteRule [P]` changes a request into a proxy request | The tested Apache path can miss the matching `<Proxy>` access rule | httpd-rs applies the matching proxy access rule | Verify that the intended users can still reach the rewritten route. |

## Unsupported policy is not ignored

| Situation | httpd-rs result |
|---|---|
| Unknown directive | Configuration loading stops. |
| Recognized directive whose effect is not implemented | Configuration loading stops. |
| Unsupported content handler or output filter | The request returns `500`. httpd-rs does not serve the source file. |
| Unsupported rule in `.htaccess` | The request returns `500`. |

Do not delete an access, authentication, TLS, proxy, handler, or filter rule
only to make the configuration load. Either reproduce the rule safely in the
supported configuration or continue to use Apache.

## Deployment changes that commonly affect a migration

| Area | httpd-rs requirement | Required action |
|---|---|---|
| Operating system | httpd-rs runs only on Linux 5.9 or newer. It does not support Windows or macOS. | Confirm the host meets these requirements. |
| Package availability | Published packages cover specific Linux distributions, CPU architectures, and C libraries. | Check the [release page](https://github.com/JD-P/httpd-rs/releases) for a matching package. |
| Debian enabled-site symlinks | httpd-rs does not follow general symlinks while loading privileged configuration | Use `httpd-rsctl`; it creates a controlled temporary copy below `/run/httpd-rs`. |
| Service installation | Installing the package does not start httpd-rs, stop Apache, or edit Apache configuration | Use `httpd-rs-switch` only after the evaluation succeeds. |
| Configuration and key files | Trusted configuration, keys, maps, and password files must not be writable by untrusted users | Correct ownership and permissions before starting httpd-rs. |
| `.htaccess` | Access-file processing is off by default | Prefer the main configuration, or enable `AccessFiles` when the site still needs `.htaccess`. |
| PHP-FPM and other FastCGI backends | The backend must use a protected Unix socket and must not modify executable application code | Protect the socket and separate writable data from executable code. |
| Long-lived connections | A WebSocket can close during configuration reload | Ensure the client reconnects. |
| TLS and Certbot | Renewal must reload httpd-rs instead of Apache | Follow [Migrate TLS and Certbot](../how-to/migrate-tls-and-certbot.md). |

## Ask your agent to check a complete site

Give your coding agent the Apache module and include dumps, the configuration
tree, the `httpd-rsctl configtest` output, the httpd-rs source revision, and this
page.

Ask it to return a table with one row for every module, handler, filter, and
default-off capability that the site uses. Each row must state:

- whether httpd-rs supports the behavior;
- the configuration or deployment change required;
- the security rule that the change must preserve;
- the positive and negative requests that test the result;
- whether the item prevents a switch.

Ask the agent to cite this documentation or a httpd-rs source file and test for
each support claim. Treat an item with no evidence as unresolved.

## How to check one site

1. Run `apache2ctl configtest` and correct existing Apache errors.
2. Run `httpd-rsctl configtest` against the complete configuration.
3. Read what every reported capability enables before you add it.
4. Resolve every rejected directive without removing required security policy.
5. Run the [deployment tutorial](../tutorials/README.md) for the application or
   connection type.
6. Test the site's important operations through httpd-rs.
7. Keep the [Apache rollback procedure](../how-to/roll-back-to-apache.md)
   available during the switch.

Absence from this page is not a support claim. Use the configuration test and a
representative application test for the complete deployment.
