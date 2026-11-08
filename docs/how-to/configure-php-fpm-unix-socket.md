---
doc_type: how-to
audience: php-operator
status: draft
contracts: DOC-HOWTO-FCGI-SOCKET-001
---

# Configure a protected PHP-FPM Unix socket

Use this procedure to let Vapache authenticate one PHP-FPM pool. Do not use a
TCP FastCGI endpoint for this connection. Four automated application deployment
tests exercise this procedure.

## Prerequisites

Install Vapache and PHP-FPM on a Linux host. Create a deployment identity that
does not run PHP-FPM. Obtain administrative access to both service
configurations.

## 1. Select the identities

Use a separate operating-system identity for each role:

| Role | Example numeric user ID |
|---|---:|
| PHP-FPM backend | `33` |
| Root owner of the socket | `0` |
| Application release owner | `1001` |

Obtain the actual numeric IDs on the target host:

```console
$ id -u www-data
$ id -u app-release
```

The PHP-FPM backend must not own or modify the application release. The
release owner must not control the PHP-FPM socket.

## 2. Configure the PHP-FPM pool

Set one exact Unix socket and the backend identity in the pool configuration:

```ini
user = www-data
group = www-data
listen = /run/php/example-fpm.sock
listen.owner = root
listen.group = www-data
listen.mode = 0660
```

Restart PHP-FPM. Then inspect the endpoint:

```console
$ sudo systemctl restart php8.4-fpm.service
$ sudo stat -Lc '%F %u:%g %a %n' /run/php/example-fpm.sock
socket 0:33 660 /run/php/example-fpm.sock
```

Use the service and version names that your distribution provides.

## 3. Declare the stable path

Enable FastCGI and bind the socket to the expected identities:

```apache
VapacheCapability FastCgi On
VapacheFastCGIStablePath On unix:/run/php/example-fpm.sock 33 0 0 1001
```

The arguments after the endpoint are the backend user ID, endpoint owner user
ID, and trusted release-tree owner user IDs. Replace the example IDs with the
values from the target host.

Configure the handler only for the immutable PHP application tree. Keep
uploads and generated files outside that handler mapping.

## 4. Test the boundary

Run:

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ curl --fail --show-error https://www.example.test/status.php
```

Confirm that the response is application output and not PHP source. Remove the
temporary status endpoint after the test.

Vapache checks the Unix-socket type, owner, inode, and peer credentials. It
also checks the script path and its ancestors. A writable executable path,
unexpected socket replacement, or unexpected peer identity fails closed.

## 5. Keep the policy active

Do not set `VapacheFastCGIStablePath Off` to resolve an ownership error. Do not
enable the unstable FastCGI path capability unless the deployment has a
separate trust analysis for unauthenticated backends.

Use [Replace an unsafe writable PHP layout](replace-writable-php-layout.md) if
the PHP process can update application code.

## Evidence

The canonical [WordPress](../tutorials/wordpress-php-fpm.md),
[Drupal](../tutorials/drupal-php-fpm.md), and
[Nextcloud](../tutorials/nextcloud-php-fpm.md) deployments use protected
PHP-FPM Unix sockets. The canonical
[Bugzilla](../tutorials/bugzilla-fastcgi.md) deployment tests the same stable
FastCGI boundary with a non-PHP application.
