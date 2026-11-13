---
doc_type: how-to
audience: apache-operator
status: draft
---

# Decide whether httpd-rs is worth testing for your site

This guide is for Apache operators who want to know whether httpd-rs might fit
their site. A new Apache advisory is one reason to consider a switch. Other
reasons include accumulated security concerns, a platform review, or a planned
server replacement.

The guide helps you decide whether to test httpd-rs with your current
configuration and application. It does not change the running Apache service.

httpd-rs is an independent reimplementation of the core features of Apache HTTP
Server 2.4 in Rust. It reads Apache configuration for the features that it
supports. It does not use code from the Apache server implementation.

httpd-rs is pre-release software. It does not contain Apache server code, so a
defect in that code is not present in httpd-rs. httpd-rs can have different
defects of its own.

## Prerequisites

You need the complete Apache configuration and a machine or virtual machine on
which you can test the site. A non-production host is safest.

If you test on the current host, keep a second SSH session or the hosting
provider's console open while you change the web service. Keep the current
Apache packages and service configuration available for rollback.

If a new advisory prompted the test, obtain the official advisory and patch
information when it is public.

## 1. Record what the site needs

Record:

- the Linux distribution and kernel version;
- the loaded Apache modules;
- the included configuration files and virtual hosts;
- whether the site serves static files or uses CGI, FastCGI, PHP-FPM, or a
  reverse proxy;
- the application operations that must continue to work;
- the maximum acceptable interruption during a switch and rollback.

Run these Apache commands to collect the configuration summary:

```console
$ sudo apache2ctl -M
$ sudo apache2ctl -t -D DUMP_INCLUDES
$ sudo apache2ctl -t -D DUMP_VHOSTS
$ sudo apache2ctl -t -D DUMP_RUN_CFG
```

If an advisory prompted the test, also record its CVE ID, affected Apache
versions, affected module or feature, required configuration, and attack
preconditions. Some early advisories do not disclose enough information for a
firm conclusion.

## 2. Check the basic requirements

- httpd-rs currently runs only on Linux with kernel 5.9 or newer. It does not
  support Windows or macOS. Check the [release
  page](https://github.com/JD-P/httpd-rs/releases) for a package that matches
  your Linux distribution, CPU architecture, and C library.
- Do not plan a switch if the site needs an Apache module, directive, or
  behavior that httpd-rs [rejects or intentionally
  changes](../reference/apache-compatibility.md).
- httpd-rs is not suitable if you require long-term-support releases or
  enterprise support.

## 3. Ask your agent to compare a new advisory

Skip this step when no specific Apache advisory prompted the test.

Give your coding agent:

- the official advisory and patch, when the patch is public;
- the httpd-rs source revision that you intend to run;
- the Apache configuration summary from step 1.

Ask the agent to return a short report that:

1. states the affected Apache component, cause, and attack preconditions;
2. identifies whether httpd-rs implements the affected feature and names the
   corresponding source files;
3. identifies any library or external service used by both servers;
4. checks whether the affected input can reach httpd-rs's unsafe Rust or a
   native dependency;
5. cites the httpd-rs tests or machine-checked properties that apply;
6. classifies the result as one of these outcomes:
   - *the affected code is absent*;
   - *the corresponding httpd-rs behavior needs testing*;
   - *a shared component needs action*;
   - *httpd-rs will not fix the problem because the cause is outside the web
     server*;
   - *the available information is not sufficient*;
7. lists the configuration and application tests needed before a switch.

The following table explains how to interpret the report:

| Advisory describes | What the result means for httpd-rs | Expected report result |
|---|---|---|
| Memory corruption in Apache's C implementation | httpd-rs does not contain the affected Apache code. More than 99% of the httpd-rs server source is safe Rust, which prevents classic C memory-corruption bugs such as use-after-free, double-free, and out-of-bounds memory access. The agent should check the small unsafe boundary and external dependencies that process the affected input. | The affected code is absent. |
| An error in an in-process module that httpd-rs does not load, such as `mod_php` or `mod_wsgi` | The configuration test confirms whether the site can run without the module. | The affected code is absent. |
| An HTTP, proxy, rewrite, access-control, TLS, CGI, or FastCGI logic error | httpd-rs can implement the same behavior independently. Ask your agent to run a focused test of the corresponding httpd-rs behavior. | The corresponding httpd-rs behavior needs testing. |
| A defect in a library or external service used by both servers | Reimplementation does not remove the defect. Update, disable, or mitigate the shared component. | A shared component needs action. |
| A configuration mistake or unsafe application layout | Correct the configuration or application layout. | httpd-rs will not fix the problem because the cause is outside the web server. |
| An early advisory that does not identify the cause or affected feature | Wait for more information while you test whether httpd-rs supports the site. | The available information is not sufficient. |

An early advisory can omit the cause or affected feature. In that case, the
available information does not establish that switching servers fixes the
incident. You can still test whether httpd-rs supports the site while you wait
for more information.

## 4. Test the existing configuration

First, confirm that Apache accepts its current configuration:

```console
$ sudo apache2ctl configtest
Syntax OK
```

Then run the httpd-rs check:

```console
$ sudo httpd-rsctl configtest
Syntax OK
```

This command reads the complete Apache configuration. It does not stop Apache
or edit files below `/etc/apache2` or `/etc/httpd`.

If httpd-rs reports an error, [Assess an Apache
configuration](assess-apache-configuration.md) explains how to identify the
unsupported directive, disabled feature, unsafe file permission, or missing
runtime file. Do not remove an access or authentication rule only to make the
test pass.

## 5. Ask your agent to prepare the migration report

Give your coding agent:

- the Apache command output from step 1;
- the complete configuration tree;
- the output from both configuration tests;
- [Apache compatibility and intentional
  differences](../reference/apache-compatibility.md).

Ask it to return:

- every unsupported module, directive, handler, and filter;
- each `HttpdRsCapability` setting that the site needs and the feature that the
  setting enables;
- every file whose ownership or permissions must change;
- every required application, TLS, logging, and reload test;
- a list of security rules that must remain effective after any configuration
  change;
- a go/no-go recommendation with unresolved items listed separately.

The report must not recommend deleting a security rule only to make the
configuration load.

## 6. Test the application before switching

Choose the [deployment tutorial](../tutorials/README.md) for your application or
for the same connection type. Run it on a test host.

Test the operations that would cause the most harm if they failed. For a
dynamic application, these usually include:

- login and logout;
- permission checks for more than one user role;
- state-changing forms or API requests;
- uploads and downloads;
- redirects and public URL generation;
- background jobs;
- WebSocket reconnection, if used;
- certificate renewal;
- service reload.

A successful home-page request is not sufficient.

## 7. Make the decision

httpd-rs is worth a controlled switch test when the configuration test passes,
the required features are supported, the application tests pass, and the
independent implementation reduces the risk that concerns you.

Continue to use Apache when an important feature is unsupported, application
behavior remains untested, the advisory cause is also present in httpd-rs, or
the operational risk of pre-release software is greater than the Apache risk
you are trying to reduce.

If you continue, run the [Debian static-site migration
tutorial](../tutorials/migrate-debian-static-site.md) to learn the service switch
and rollback procedure. Then use [Migrate TLS and
Certbot](migrate-tls-and-certbot.md) and the tutorial for your application.
