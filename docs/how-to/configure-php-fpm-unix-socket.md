---
doc_type: how-to
audience: php-operator
status: draft
contracts: DOC-HOWTO-FCGI-SOCKET-001
---

# Configure a protected PHP-FPM Unix socket

Use this procedure to connect httpd-rs to one PHP-FPM pool through a protected
Unix socket. The socket settings let httpd-rs reject a replaced endpoint or an
unexpected backend process.

## Prerequisites

Install httpd-rs and PHP-FPM on a Linux host. Create a deployment identity that
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
HttpdRsCapability FastCgi On
HttpdRsFastCGIStablePath On unix:/run/php/example-fpm.sock 33 0 0 1001
```

The arguments after the endpoint are the backend user ID, endpoint owner user
ID, and trusted release-tree owner user IDs. Replace the example IDs with the
values from the target host.

Configure the handler only for the immutable PHP application tree. Keep
uploads and generated files outside that handler mapping.

## 4. Test the boundary

Run:

```console
$ sudo httpd-rsctl configtest
$ sudo systemctl reload httpd-rs.service
$ curl --fail --show-error https://www.example.test/status.php
```

Confirm that the response is application output and not PHP source. Remove the
temporary status endpoint after the test.

httpd-rs checks the Unix-socket type, owner, inode, and peer credentials. It
also checks the script path and its ancestors. A writable executable path,
unexpected socket replacement, or unexpected peer identity fails closed.

## 5. Resolve a failed identity check

If httpd-rs reports an unexpected owner or peer, compare the error with the
`id` and `stat` output from steps 1 and 2. Correct the PHP-FPM pool or socket
ownership. Turning off `HttpdRsFastCGIStablePath` removes the endpoint identity
check rather than fixing the mismatch.

Use [Replace an unsafe writable PHP layout](replace-writable-php-layout.md) if
the PHP process can update application code.

<!--
Behavior contract deployment evidence:
[WordPress](../tutorials/wordpress-php-fpm.md)
[Drupal](../tutorials/drupal-php-fpm.md)
[Nextcloud](../tutorials/nextcloud-php-fpm.md)
[Bugzilla](../tutorials/bugzilla-fastcgi.md)
-->
