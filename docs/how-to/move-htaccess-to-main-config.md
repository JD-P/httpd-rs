---
doc_type: how-to
audience: apache-operator
status: draft
contracts: DOC-HOWTO-HTACCESS-001
---

# Move `.htaccess` policy into the main configuration

Use this procedure to move `.htaccess` rules into the main configuration and
then stop httpd-rs from reading access files in that document tree.

## Prerequisites

Obtain the complete main configuration, all included files, and all served
trees. Record representative permitted and denied requests before you change
the policy.

## 1. Record the active policy

Find every configured access-file name and every file in the served trees:

```console
$ sudo apache2ctl -t -D DUMP_INCLUDES
$ find /srv/www -name .htaccess -type f -print
$ grep -R -E '^[[:space:]]*(AccessFileName|AllowOverride|AllowOverrideList)' /etc/apache2
```

Repeat the search for a non-default `AccessFileName`. Record the effective
`AllowOverride` and `AllowOverrideList` for each directory.

Apache's [access-file
guide](https://httpd.apache.org/docs/2.4/howto/htaccess.html) explains when
Apache reads `.htaccess` files. The directive references define
[`AccessFileName`](https://httpd.apache.org/docs/2.4/mod/core.html#accessfilename),
[`AllowOverride`](https://httpd.apache.org/docs/2.4/mod/core.html#allowoverride),
and
[`AllowOverrideList`](https://httpd.apache.org/docs/2.4/mod/core.html#allowoverridelist).
Use those definitions to record the Apache baseline before you move a rule.

## 2. Classify each directive

For each access file, record:

- the directory where Apache reads the file;
- the directive order;
- the permitted override category;
- the requests that the rule permits, denies, redirects, or rewrites.

Stop if the file contains a directive that httpd-rs rejects. Do not delete an
access-control or authentication rule to make the configuration load.

## 3. Move the policy into its directory context

Copy the directives, in the same order, into the matching `<Directory>` block
in the main configuration. Then set `AllowOverride None` for that tree.

Use Apache's [`<Directory>`
reference](https://httpd.apache.org/docs/2.4/mod/core.html#directory) to preserve
the original filesystem scope.

```apache
<Directory /srv/www/example/public>
    AllowOverride None
    Require all granted

    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^ index.php [L]
</Directory>
```

Do not add a leading slash to a per-directory rewrite pattern. Confirm the
substitution base and inherited directory context. These details can change
the target even when the regular expression is equal.

## 4. Test a staged configuration

Test the complete configuration before you change the live service:

```console
$ sudo httpd-rsctl configtest
```

Start the staged configuration on an evaluation host. Test positive and
negative cases for authentication, authorization, redirects, rewrites,
indexes, error documents, and content handlers.

## 5. Disable access-file capability

After all served trees use `AllowOverride None`, remove the `AccessFiles`
capability declaration. Run:

```console
$ sudo httpd-rsctl configtest
$ sudo systemctl reload httpd-rs.service
```

Keep the old access files until the deployment is accepted. Their presence has
no effect when the effective override policy is `None`.

<!--
Behavior contract evidence:
[Configuration semantics](../../tests/config_semantics.py)
[Hugo](../tutorials/hugo-static-site.md)
[WordPress](../tutorials/wordpress-php-fpm.md)
[Drupal](../tutorials/drupal-php-fpm.md)
-->
