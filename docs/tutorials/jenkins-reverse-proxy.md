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

You will install Jenkins LTS and Java, bind Jenkins to loopback, set its context
path, configure the Vapache route, complete the Jenkins setup, create a job,
reload Vapache, and verify the job through the API.

## Before you start

Complete [Prepare a Debian VPS for a Vapache
tutorial](prepare-debian-vps.md). Point `ci.example.test` at the VPS and open
TCP ports 80 and 443 in the provider firewall.

## 1. Install Jenkins LTS

```console
$ sudo apt install fontconfig gnupg openjdk-21-jre
$ curl --fail --show-error --location \
    https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key \
    | sudo tee /usr/share/keyrings/jenkins-keyring.asc >/dev/null
$ echo 'deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] https://pkg.jenkins.io/debian-stable binary/' \
    | sudo tee /etc/apt/sources.list.d/jenkins.list >/dev/null
$ sudo apt update
$ sudo apt install jenkins
$ sudo certbot certonly --standalone --domain ci.example.test
```

## 2. Configure the Jenkins listener and prefix

```console
$ sudo install -d -m 0755 /etc/systemd/system/jenkins.service.d
```

Create `/etc/systemd/system/jenkins.service.d/vapache.conf`:

```systemd
[Service]
Environment="JENKINS_OPTS=--httpListenAddress=127.0.0.1 --httpPort=8080 --prefix=/jenkins"
```

Start Jenkins and confirm that the private endpoint responds:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable jenkins.service
$ sudo systemctl restart jenkins.service
$ curl -I http://127.0.0.1:8080/jenkins/login
```

The explicit restart applies the loopback listener and `/jenkins` prefix even
if the package started Jenkins during installation.

## 3. Configure Vapache

Create `/etc/apache2/sites-available/jenkins.conf`:

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

Enable the virtual host, test the configuration, and start Vapache:

```console
$ sudo a2ensite jenkins.conf
$ sudo vapachectl configtest
$ sudo systemctl enable --now vapache.service
```

## 4. Complete Jenkins setup

Read the initial administrator password:

```console
$ sudo cat /var/lib/jenkins/secrets/initialAdminPassword
```

Open `https://ci.example.test/jenkins/`, enter that password, install the
suggested plugins, and create the first administrator. In **Manage Jenkins →
System → Jenkins URL**, set `https://ci.example.test/jenkins/`.

## 5. Test an authenticated state change

```console
$ curl -I https://ci.example.test/jenkins/login
```

Sign in through the public URL, create a small freestyle job, and save it. This
tests the session cookie, CSRF token, form body, and public redirects together.

Reload Vapache. Open the job again and request its JSON API through the public
URL. Confirm that the session remains valid and that no redirect exposes port
`8080`.

<!--
Deployment contract only; not operator instructions.
--scenario jenkins-proxy
Documentation case: `mount=subpath`, `reload=after-start`, `benchmark=job`.
Scenario storage budget: 2048 MiB.
[Scenario](../../tests/deployments/scenarios/jenkins-proxy/scenario.toml)
[Driver](../../tests/deployments/scenarios/jenkins-proxy/driver.py)
-->
