# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG SOURCE_PACKAGE
ARG EXPECTED_VERSION
ARG BINARY_PACKAGES
ARG APT_SOURCES_B64
ENV DEBIAN_FRONTEND=noninteractive
RUN --mount=type=secret,id=runner-ca,target=/tmp/getpatched-runner-ca.crt,required=true \
    set -eu; \
    mkdir -p /etc/ssl/certs; \
    cp /tmp/getpatched-runner-ca.crt /etc/ssl/certs/ca-certificates.crt; \
    chmod 0644 /etc/ssl/certs/ca-certificates.crt; \
    printf 'Acquire::https::CAInfo "/etc/ssl/certs/ca-certificates.crt";\n' > /etc/apt/apt.conf.d/99getpatched-ca; \
    test -n "$APT_SOURCES_B64"; \
    test -n "$BINARY_PACKAGES"; \
    printf '%s' "$APT_SOURCES_B64" | base64 -d > /etc/apt/sources.list; \
    apt-get update; \
    apt-get -y dist-upgrade; \
    apt-get install -y --no-install-recommends build-essential python3 valgrind pkg-config; \
    for binary in $BINARY_PACKAGES; do \
      candidate="$(apt-cache policy "$binary" | awk '/Candidate:/ {print $2}')"; \
      test "$candidate" = "$EXPECTED_VERSION" || { \
        echo "Public candidate changed for $binary: $candidate (expected $EXPECTED_VERSION); refresh preflight, do not downgrade." >&2; \
        exit 1; \
      }; \
    done; \
    for binary in $BINARY_PACKAGES; do apt-get install -y --no-install-recommends "$binary=$EXPECTED_VERSION"; done; \
    dpkg-query -W $BINARY_PACKAGES 2>/dev/null || true; \
    rm -rf /var/lib/apt/lists/*
