FROM debian:13-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

ENV container=docker
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apache2 curl javascript-common php-fpm systemd systemd-sysv \
    && rm -rf /var/lib/apt/lists/*

RUN a2enmod proxy_fcgi setenvif \
    && set -- /etc/apache2/conf-available/php*-fpm.conf \
    && a2enconf "$(basename "$1" .conf)"

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
