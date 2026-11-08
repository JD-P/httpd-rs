---
doc_type: landing
audience: apache-operator
status: draft
---

# Vapache how-to guides

Use these guides when you have a specific task. If you have not tested the
complete Apache configuration, start with [Decide whether to replace Apache
with Vapache](evaluate-security-driven-migration.md).

## Evaluate and migrate an Apache site

| Task | Guide |
|---|---|
| Decide whether Vapache is suitable after a new Apache incident | [Decide whether to replace Apache with Vapache](evaluate-security-driven-migration.md) |
| Find configuration and deployment blockers | [Assess an Apache configuration](assess-apache-configuration.md) |
| Preserve HTTPS and certificate renewal | [Migrate TLS and Certbot](migrate-tls-and-certbot.md) |
| Resolve a rejected directive | [Investigate a rejected directive](investigate-rejected-directive.md) |
| Return traffic to Apache | [Roll back to Apache](roll-back-to-apache.md) |

## Operate applications and the service

| Task | Guide |
|---|---|
| Reload configuration, reopen logs, stop the service, or diagnose startup | [Operate the Vapache service](operate-vapache-service.md) |
| Permit only Vapache to connect to PHP-FPM | [Configure a protected PHP-FPM Unix socket](configure-php-fpm-unix-socket.md) |
| Stop PHP from modifying executable application code | [Replace an unsafe writable PHP layout](replace-writable-php-layout.md) |
| Move `.htaccess` rules into the main configuration | [Move `.htaccess` policy into the main configuration](move-htaccess-to-main-config.md) |
| Send the correct public URL information to a proxied application | [Configure forwarded headers for a reverse proxy](configure-proxy-authority.md) |

## For project security reviewers

[Add a new Apache CVE to the project review](evaluate-apache-cve.md) explains
how maintainers update the checked-in CVE analysis. It is not required for an
administrator who is evaluating a migration.
