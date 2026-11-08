---
doc_type: how-to
audience: apache-operator
status: draft
contracts: DOC-CAPABILITY-AUDIT-001, DOC-UNSUPPORTED-POLICY-001
---

# Assess an Apache configuration

Use this procedure before you stop Apache or start Vapache. The procedure finds
required Vapache features, unsupported directives, configuration files with
unsafe ownership or permissions, and deployment changes.

## Prerequisites

You need a working Apache site and administrative shell access to its host.

## 1. Test Apache first

Run the Apache configuration test.

```console
$ sudo apache2ctl configtest
Syntax OK
```

## 2. Record what Apache currently loads

Record the loaded modules, included files, and virtual hosts.

```console
$ sudo apache2ctl -M
$ sudo apache2ctl -t -D DUMP_INCLUDES
$ sudo apache2ctl -t -D DUMP_VHOSTS
$ sudo apache2ctl -t -D DUMP_RUN_CFG
```

Save this output. You will use it to compare Apache with Vapache. The
loaded-module list can reveal Apache features that are compiled into the server
or enabled outside the site's virtual-host file.

## 3. Run the packaged Vapache check

Run:

```console
$ sudo vapachectl configtest
```

**Nonstandard configuration location:** If your Apache configuration is not at
`/etc/apache2/apache2.conf` on a Debian-family system or
`/etc/httpd/conf/httpd.conf` on an RPM-family system, set `VAPACHE_CONFDIR` to
the configuration directory and `VAPACHE_CONFIG` to the main configuration
file before you run the check.

Some features that Apache enables by default are off by default in Vapache
because they add attack surface but are needed only by some configurations.
Vapache calls these features *capabilities*. When the configuration needs one,
the wrapper adds the required `VapacheCapability` line to a temporary test copy
and prints the line. It does not change the Apache configuration.

## 4. Check a copied configuration for required capabilities

Skip this section if you used `sudo vapachectl configtest` above. Use
`--audit-capabilities` only when you are checking a copied configuration file
directly with `vapached -f`.

Run:

```console
$ vapached -f /path/to/copied-httpd.conf --audit-capabilities
```

Replace `/path/to/copied-httpd.conf` with the path to the copied main
configuration file. The command lists the capabilities that the copied
configuration requires without enabling them or changing the file. For each
reported capability, confirm that the site needs the feature. If it does, add
the printed line to the main server configuration.

Audit mode cannot start a runnable server. Vapache capabilities must be enabled
in the main server configuration. An `.htaccess` file cannot enable them.

### Example: a configuration that requires CGI

Suppose the copied Apache configuration contains this CGI rule:

<!-- tested-example: compatibility/capability-cgi.conf -->

```apache
ScriptAlias "/cgi-bin/" "/srv/www/example/cgi-bin/"
```

The capability audit reports this required declaration:

```text
VapacheCapability Cgi On
```

## 5. Resolve each Vapache error

Use these categories:

| Error category | Meaning | Action |
|---|---|---|
| Missing capability | The configuration requests a supported feature that Vapache disables by default | Decide whether the site needs the feature. If it does, add the reported `VapacheCapability` line to the main configuration. |
| Recognized but unsupported directive | Vapache cannot preserve the directive effect | Change the deployment or continue to use Apache. Do not delete a policy directive only to make the test pass. |
| Invalid or unknown directive | Vapache does not recognize a valid supported use of the directive | Correct the configuration, or continue to use Apache when Vapache lacks the feature. |
| Unsafe configuration input | The file has unsafe ownership, write access, type, symlink use, size, or path stability | Move or secure the file. Do not weaken the check without documenting who can change the file and what that access permits. |
| Unsupported location or value | Vapache cannot give the directive the same meaning that Apache gives it in this location | Move the directive only when Apache permits the move without changing behavior. Otherwise, change the deployment. |
| Missing runtime file | A certificate, key, password file, map, MIME database, or include is absent | Supply the same file that the running deployment requires. |

For example, Vapache rejects this Apache policy directive because Vapache does
not implement its effect:

<!-- tested-example: compatibility/unsupported-policy.conf -->

```apache
SSLRequireSSL
```

Vapache stops configuration loading instead of ignoring the directive.

## 6. Ask your agent to resolve unclear errors

Give your coding agent:

- the complete Vapache error;
- the directive and its enclosing configuration blocks;
- the Apache include and module dumps from step 2;
- the Vapache source revision;
- [Apache compatibility and intentional
  differences](../reference/apache-compatibility.md).

Ask the agent to return:

- the effect that Apache applies at that location;
- whether Vapache supports the same effect;
- the supported configuration or deployment change that preserves the effect;
- a negative and positive request test for the result;
- a clear statement when Vapache cannot support the site without weakening the
  rule.

The answer must not recommend deleting an access, authentication, TLS, proxy,
handler, or filter rule only to make the configuration load.

## 7. Review differences that require a deployment change

Read [Apache compatibility and intentional differences](../reference/apache-compatibility.md).
Review at least these areas:

- default-off capabilities;
- unsupported modules and handlers;
- configuration symlinks and administrative-input ownership;
- `.htaccess` use;
- CGI and FastCGI execution;
- writable application code;
- TLS and Certbot;
- reload behavior for long-lived connections;
- process and resource limits.

## 8. Verify a representative workflow

Do not use a successful configuration test as the final acceptance test. Start
Vapache on an evaluation host and test the workflows that matter to the site.

For a static site, test the home page, a missing page, redirects, authentication,
ranges, and cache policy. For a dynamic application, test login, state change,
upload, download, background work, and reload.

Use the [deployment tutorial catalog](../tutorials/README.md) to select tests for
the application or for another application that connects to the server in the
same way.
