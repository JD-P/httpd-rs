---
doc_type: how-to
audience: php-operator
status: draft
contracts: DOC-HOWTO-PHP-LAYOUT-001
---

# Replace an unsafe writable PHP layout

Use this procedure when PHP-FPM can modify PHP code, a plugin directory, or an
ancestor of the document root. Automated WordPress, Drupal, and Nextcloud
deployment tests exercise this layout.

## Prerequisites

Create a tested backup of the application and its data. Prepare a deployment
identity that is different from the PHP-FPM identity. Record the current
virtual-host configuration and release path.

## 1. Find writable paths

Run the check as the PHP-FPM identity:

```console
$ sudo -u www-data find /srv/example -xdev -writable -print
```

Also inspect ownership and access-control lists:

```console
$ find /srv/example -xdev -printf '%u:%g %m %p\n'
$ getfacl -R -p /srv/example
```

Treat a writable ancestor as part of the finding. The backend can replace a
protected child when it can rename entries in the parent directory.

## 2. Ask your agent to classify writable paths

Give your coding agent the application name and version, the output from the
commands in step 1, the package or deployment documentation, and the virtual
host.

Ask the agent to classify every writable path as:

- executable application code that must become read-only;
- uploads or generated data that must remain writable;
- cache or temporary data that can move outside the release;
- an update or plugin path that requires a separate deployment process;
- an unknown path that needs an application-specific test.

Ask it to produce a release-and-data directory plan and a request test that
confirms PHP execution is denied in every writable public directory.

## 3. Create release and data trees

Use separate paths:

```text
/srv/example/releases/2026-11-07/    immutable application release
/srv/example/shared/uploads/          writable application data
```

Create the release as a deployment identity that is not the PHP-FPM identity.
Give PHP-FPM read and search access to the release. Give PHP-FPM write access
only to the required data paths.

Do not place a writable cache, upload, plugin, theme, or update directory under
a FastCGI handler that can execute its files.

## 4. Deny execution in writable data

Map the writable path explicitly and deny PHP files in it. For example:

```apache
Alias /uploads/ /srv/example/shared/uploads/

<Directory /srv/example/shared/uploads>
    Require all granted
    AllowOverride None
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</Directory>
```

Keep the PHP handler mapping limited to the immutable release tree. Some
applications require a non-executable data directory outside the public URL;
prefer that layout when the application supports it.

## 5. Select the new release

Update the virtual host to name the versioned release. Do not use an
application-controlled symlink as the release selector.

Run:

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
```

Test login, uploads, generated files, and application jobs. Request a test
file with a `.php` suffix from every writable public path and confirm that the
server denies it.

## 6. Change the update process

Build plugins, themes, modules, and application upgrades outside the running
PHP process. Deploy a new immutable release and change the configured release
path after validation.

An application dashboard that writes executable code is outside this model.
Disable that function or continue to use a server and isolation boundary that
matches the accepted risk.

## Roll back the release change

Restore the previous versioned release path in the virtual host. Run the
configuration test and reload Vapache. Do not restore write access to
executable code as a rollback method.

## Evidence

The canonical [WordPress](../tutorials/wordpress-php-fpm.md),
[Drupal](../tutorials/drupal-php-fpm.md), and
[Nextcloud](../tutorials/nextcloud-php-fpm.md) scenarios exercise uploads and
application workflows while the application code remains immutable to the
backend.
