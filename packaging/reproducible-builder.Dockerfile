# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM rust:1.99.1-trixie@sha256:09027f873d45b8ecd1dc86f1fa13b7a62b875c961f017a0e331267b350430137

# The base image and every package version are immutable inputs. If the mirror
# no longer carries one of these exact versions, the build fails instead of
# silently accepting a different packaging toolchain.
RUN --mount=type=secret,id=proxy_ca,required=false,mode=0444 \
    if [ -s /run/secrets/proxy_ca ]; then \
        export SSL_CERT_FILE=/run/secrets/proxy_ca; \
        export CARGO_HTTP_CAINFO=/run/secrets/proxy_ca; \
    fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils=2.44-3 \
        debugedit=1:5.1-2 \
        dpkg-dev=1.22.22 \
        file=1:5.46-5 \
        libarchive13t64=3.7.4-4+deb13u1 \
        libdbus-1-3=1.16.2-2 \
        libdw1t64=0.192-4 \
        libfsverity0=1.6-1.2 \
        liblua5.3-0=5.3.6-2+b4 \
        libpopt0=1.19+dfsg-2 \
        librpm-sequoia-1=1.8.0-2 \
        librpm10=4.20.1+dfsg-3 \
        librpmbuild10=4.20.1+dfsg-3 \
        librpmio10=4.20.1+dfsg-3 \
        librpmsign10=4.20.1+dfsg-3 \
        musl=1.2.5-3.1~deb13u1 \
        musl-dev=1.2.5-3.1~deb13u1 \
        musl-tools=1.2.5-3.1~deb13u1 \
        python3=3.13.5-1 \
        rpm=4.20.1+dfsg-3 \
        rpm-common=4.20.1+dfsg-3 \
        rpm2cpio=4.20.1+dfsg-3 \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl

# Cache only Cargo.lock-verified sources in the builder. The release run below
# is network-isolated and therefore cannot acquire different build inputs.
WORKDIR /opt/httpd-rs-source
COPY . .
RUN --mount=type=secret,id=proxy_ca,required=false,mode=0444 \
    if [ -s /run/secrets/proxy_ca ]; then \
        export SSL_CERT_FILE=/run/secrets/proxy_ca; \
        export CARGO_HTTP_CAINFO=/run/secrets/proxy_ca; \
    fi \
    && cargo fetch --locked --target x86_64-unknown-linux-musl

WORKDIR /src
