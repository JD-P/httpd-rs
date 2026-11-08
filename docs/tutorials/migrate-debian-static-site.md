---
doc_type: tutorial
audience: apache-operator
status: draft
contracts: DOC-MIGRATE-STATIC-001
---

# Migrate a Debian static site in an evaluation environment

In this tutorial, you migrate one Apache virtual host to Vapache. The host is
`www.example.test`. It serves an immutable static release from
`/srv/www/example/releases/2026-11-07/public`.

The tutorial keeps the existing Apache configuration. The Vapache package
creates a runtime snapshot when the Debian configuration uses enabled-file
symlinks. The switch tool can restore the previous Apache service state if the
Vapache start fails.

Use a non-production host when possible. If you test on the current host, keep
a second SSH session or the hosting provider's console open during the switch.

## What you will do

You will:

1. verify the existing site through Apache;
2. test the Apache configuration with Vapache;
3. inspect the service transition;
4. switch the host to Vapache;
5. verify the same site through Vapache;
6. restore Apache.

## Before you start

You need:

- Debian with `apache2.service` active;
- a Vapache package that matches the checked-out source version;
- root access through `sudo`;
- a second SSH session or hosting-provider console for recovery;
- the name or address of the evaluation host.

The example site uses this virtual host. The documentation test starts the real
`vapached` binary with this configuration and verifies its HTTP behavior.

<!-- tested-example: migrate-debian-static-site/vhost.conf -->

```apache
<VirtualHost *:80>
    ServerName www.example.test
    DocumentRoot "/srv/www/example/releases/2026-11-07/public"
    ErrorDocument 404 /404.html

    <Directory "/srv/www/example/releases/2026-11-07/public">
        Options -Indexes -ExecCGI
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
```

The `DocumentRoot` is immutable to the service identity. This tutorial does not
enable `.htaccess`, CGI, FastCGI, autoindex, or another default-off capability.

## 1. Record the Apache state

Record the service state before you change it.

```console
$ systemctl is-active apache2.service
active
$ systemctl is-enabled apache2.service
enabled
```

If the second command reports `disabled`, record that state. The switch tool
uses the current active and enabled states for automatic recovery.

## 2. Verify the Apache configuration

Test the complete Apache configuration.

```console
$ sudo apache2ctl configtest
Syntax OK
```

Do not continue if Apache reports an error.

## 3. Verify the site through Apache

Send a request to the evaluation host. Replace `EVALUATION_IP` with its address.

```console
$ curl --fail --show-error --resolve www.example.test:80:EVALUATION_IP \
    http://www.example.test/
Vapache documentation example
```

The command must return the expected page before the service transition.

## 4. Test the configuration with Vapache

Run the packaged Vapache configuration test.

```console
$ sudo vapachectl configtest
Syntax OK
```

On Debian, `vapachectl` materializes the selected Apache configuration below
`/run/vapache`. It does not edit `/etc/apache2`. If the configuration requests a
default-off capability, `vapachectl` prints each capability that it adds to the
runtime snapshot.

Do not continue if the command reports an unsupported directive, unsafe input,
missing file, or invalid certificate.

## 5. Inspect the planned switch

Run the switch command without `--yes`.

```console
$ sudo vapache-switch
```

The command performs another configuration test. It then reports the detected
Apache service, the planned state change, and any Certbot integration change.
Answer `n` at the confirmation prompt.

Expected final output:

```text
No changes made.
```

## 6. Switch to Vapache

Open a second administrative connection. Keep that connection open during the
switch.

Run the switch command again and answer `y` after you inspect the plan.

```console
$ sudo vapache-switch
```

The tool disables and stops `apache2.service`. The tool then enables and starts
`vapache.service`. If Vapache does not start, the tool restores the recorded
Apache active and enabled states.

## 7. Verify Vapache

Confirm that the Vapache service is active.

```console
$ systemctl is-active vapache.service
active
```

Request the home page.

```console
$ curl --fail --show-error --resolve www.example.test:80:EVALUATION_IP \
    http://www.example.test/
Vapache documentation example
```

Request a missing path and inspect the status and custom error body.

```console
$ curl --silent --show-error --include \
    --resolve www.example.test:80:EVALUATION_IP \
    http://www.example.test/missing
```

The response must have status `404`. The body must contain
`The requested example page does not exist.`

Vapache rejects `POST` to this static file with status `405`. Apache normally
serves the file with status `200`. This difference is intentional.

```console
$ curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
    --request POST --data test \
    --resolve www.example.test:80:EVALUATION_IP \
    http://www.example.test/
405
```

## Roll back

Stop and disable Vapache.

```console
$ sudo systemctl disable --now vapache.service
```

Restore the active and enabled Apache state that you recorded in step 1. For the
example state, run:

```console
$ sudo systemctl enable --now apache2.service
```

Verify Apache again.

```console
$ sudo apache2ctl configtest
Syntax OK
$ curl --fail --show-error --resolve www.example.test:80:EVALUATION_IP \
    http://www.example.test/
Vapache documentation example
```

The Vapache package does not remove or edit the Apache configuration during the
switch.

## How this tutorial is tested

The automated documentation test starts the built Vapache server with the
example virtual host. It checks the home page, custom `404` response, and static
`POST` response through HTTP.

The package test checks that an interrupted switch restores the previous Apache
service state. The package build also installs and starts the service in the
supported distribution test environments.
