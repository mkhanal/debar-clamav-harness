ARG CLAMAV_IMAGE=docker.io/clamav/clamav-debian:1.5.4@sha256:cce3e1a43ae2bb40e11335c52c0e1e98273b12fa3d587e617f63a6907cc4b70b
ARG BUILD_IMAGE=docker.io/library/buildpack-deps:trixie@sha256:086433f3c4cca3435eba355f585f55d593751a35c865745d88ce97e7258e3fc9

FROM ${CLAMAV_IMAGE} AS reference

FROM ${BUILD_IMAGE} AS headers
ARG CLAMAV_VERSION=1.5.4
ARG CLAMAV_SOURCE_SHA256=1af1117a228f1b5bc7fa91a0dabc37848a99e7d25188e9be8043332ce721dfd3
WORKDIR /source
RUN curl --fail --location --silent --show-error --retry 3 --output clamav.tar.gz \
        "https://github.com/Cisco-Talos/clamav/releases/download/clamav-${CLAMAV_VERSION}/clamav-${CLAMAV_VERSION}.tar.gz" \
    && echo "${CLAMAV_SOURCE_SHA256}  clamav.tar.gz" | sha256sum --check --strict \
    && tar --extract --gzip --file clamav.tar.gz --strip-components=1 \
        "clamav-${CLAMAV_VERSION}/libclamav/clamav.h" \
        "clamav-${CLAMAV_VERSION}/clamav-types.h.in" \
        "clamav-${CLAMAV_VERSION}/clamav-version.h.in"
COPY configure-public-headers.sh /source/
RUN mkdir /include && sh configure-public-headers.sh /source /include

FROM ${BUILD_IMAGE} AS observer
COPY --from=reference /usr/lib/libclamav.so.12 /opt/reference/lib/libclamav.so
COPY --from=headers /include /opt/reference/include
COPY clamav-observer.c /build/
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -D_GNU_SOURCE \
        -I/opt/reference/include \
        -o /build/clamav-observer /build/clamav-observer.c \
        -L/opt/reference/lib -lclamav -Wl,--allow-shlib-undefined

FROM ${CLAMAV_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/mkhanal/debar-clamav-harness" \
      org.opencontainers.image.description="Records what libclamav 1.5.4 reaches and detects, object by object, with the official databases of the pinned clamav/clamav-debian image" \
      org.opencontainers.image.licenses="GPL-2.0-only"
COPY --from=observer /build/clamav-observer /usr/local/bin/clamav-observer
USER clamav
ENTRYPOINT ["/usr/local/bin/clamav-observer"]
