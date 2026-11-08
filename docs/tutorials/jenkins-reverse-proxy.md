---
doc_type: tutorial
audience: application-operator
status: draft
contracts: DOC-DEPLOY-JENKINS-001
scenario: jenkins-proxy
---

# Put Jenkins behind Vapache on a VPS

This tutorial publishes Jenkins below `/jenkins/` at
`https://ci.example.test/jenkins/`.

## What you will do

You will bind Jenkins to loopback, set its context path, configure the Vapache
route, create a job through Jenkins's authenticated form flow, reload Vapache,
and verify the job through the API.

## Before you start

You need a Linux VPS with Vapache, Jenkins LTS, and a certificate for
`ci.example.test`. Jenkins must already run as a systemd service.

## 1. Configure the Jenkins listener and prefix

Set the Jenkins startup options for your distribution so that they include:

```text
--httpListenAddress=127.0.0.1
--httpPort=8080
--prefix=/jenkins
```

Restart Jenkins and confirm that the private endpoint responds:

```console
$ sudo systemctl restart jenkins.service
$ curl -I http://127.0.0.1:8080/jenkins/login
```

In **Manage Jenkins → System → Jenkins URL**, set
`https://ci.example.test/jenkins/`.

## 2. Configure Vapache

```apache
<VirtualHost *:443>
    ServerName ci.example.test
    SSLEngine On
    SSLCertificateFile /etc/letsencrypt/live/ci.example.test/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/ci.example.test/privkey.pem

    ProxyPass /jenkins/ http://127.0.0.1:8080/jenkins/
    ProxyPassReverse /jenkins/ http://127.0.0.1:8080/jenkins/
</VirtualHost>
```

## 3. Test an authenticated state change

```console
$ sudo vapachectl configtest
$ sudo systemctl reload vapache.service
$ curl -I https://ci.example.test/jenkins/login
```

Sign in through the public URL, create a small freestyle job, and save it. This
tests the session cookie, CSRF token, form body, and public redirects together.

Reload Vapache. Open the job again and request its JSON API through the public
URL. Confirm that the session remains valid and that no redirect exposes port
`8080`.

## Roll back

Restore the previous Vapache route, Jenkins URL, and context-path setting.
Restart Jenkins and reload Vapache.

<!--
Deployment contract only; not operator instructions.
--scenario jenkins-proxy
Canonical dimensions: `mount=subpath`, `reload=after-start`, `benchmark=job`.
Scenario storage budget: 2048 MiB.
[Scenario](../../tests/deployments/scenarios/jenkins-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/jenkins-proxy/driver.py)
-->
