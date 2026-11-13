# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

ENV DEBIAN_FRONTEND=noninteractive

COPY DBD-MariaDB-1.24.tar.gz Template-Toolkit-3.106.tar.gz \
     entrypoint.sh checksetup_answers.txt /tmp/build-inputs/

RUN --mount=type=secret,id=proxy_ca \
    --mount=type=secret,id=system_ca \
    set -eu; \
    ca=/etc/ssl/certs/ca-certificates.crt; \
    if [ -s /run/secrets/proxy_ca ]; then \
      cat /run/secrets/system_ca /run/secrets/proxy_ca >/tmp/build-ca.pem; \
      ca=/tmp/build-ca.pem; \
    fi; \
    apt-get -o Acquire::https::CaInfo="$ca" update; \
    apt-get -o Acquire::https::CaInfo="$ca" install -y --no-install-recommends \
      ca-certificates \
      fcgiwrap \
      spawn-fcgi \
      netcat-openbsd \
      mariadb-client \
      libcgi-pm-perl \
      libtimedate-perl \
      libdatetime-perl \
      libdatetime-timezone-perl \
      libdbi-perl \
      libdbix-connector-perl \
      libmoo-perl \
      libtemplate-perl \
      libemail-sender-perl \
      libemail-address-xs-perl \
      libemail-mime-perl \
      liburi-perl \
      liblist-moreutils-perl \
      libmath-random-isaac-perl \
      libjson-xs-perl \
      libjson-rpc-perl \
      libtest-taint-perl \
      libdevel-checklib-perl \
      build-essential \
      libmariadb-dev; \
    tar -xzf /tmp/build-inputs/Template-Toolkit-3.106.tar.gz -C /tmp; \
    cd /tmp/Template-Toolkit-3.106; \
    perl Makefile.PL TT_ACCEPT=y TT_QUIET=y; \
    make -j2; \
    make install; \
    cd /tmp; \
    rm -rf /tmp/Template-Toolkit-3.106; \
    tar -xzf /tmp/build-inputs/DBD-MariaDB-1.24.tar.gz -C /tmp; \
    cd /tmp/DBD-MariaDB-1.24; \
    perl Makefile.PL --mariadb_config=/usr/bin/mariadb_config; \
    make -j2; \
    make install; \
    cd /; \
    mkdir -p /opt/httpd-rs; \
    cp /tmp/build-inputs/entrypoint.sh /usr/local/bin/httpd-rs-bugzilla-entrypoint; \
    cp /tmp/build-inputs/checksetup_answers.txt /opt/httpd-rs/checksetup_answers.txt; \
    chmod 0755 /usr/local/bin/httpd-rs-bugzilla-entrypoint; \
    rm -rf /tmp/DBD-MariaDB-1.24 /tmp/build-inputs; \
    apt-get purge -y --auto-remove build-essential libmariadb-dev libdevel-checklib-perl; \
    rm -rf /var/lib/apt/lists/*; \
    rm -f /tmp/build-ca.pem

EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/httpd-rs-bugzilla-entrypoint"]
