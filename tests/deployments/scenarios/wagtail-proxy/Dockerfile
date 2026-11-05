# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM python@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=bakerydemo.settings.production

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
      libjpeg62-turbo libpq5 shared-mime-info zlib1g; \
    rm -rf /var/lib/apt/lists/* /tmp/build-ca.pem

COPY requirements.lock /requirements.lock
RUN --mount=type=secret,id=proxy_ca \
    --mount=type=secret,id=system_ca \
    set -eu; \
    ca=/etc/ssl/certs/ca-certificates.crt; \
    if [ -s /run/secrets/proxy_ca ]; then \
      cat /run/secrets/system_ca /run/secrets/proxy_ca >/tmp/build-ca.pem; \
      ca=/tmp/build-ca.pem; \
    fi; \
    PIP_CERT="$ca" python -m pip install --no-cache-dir --requirement /requirements.lock; \
    rm -f /tmp/build-ca.pem

WORKDIR /code
COPY app /code
RUN chmod -R a+rX /code && \
    DATABASE_URL=postgres://unused:unused@127.0.0.1/unused \
    REDIS_URL= \
    DJANGO_SECRET_KEY=build-only \
    SECURE_SSL_REDIRECT=False \
    python manage.py collectstatic --noinput

USER 1000:1000
EXPOSE 8000
CMD ["gunicorn", "--bind=0.0.0.0:8000", "--workers=2", "--threads=2", "bakerydemo.wsgi:application"]
