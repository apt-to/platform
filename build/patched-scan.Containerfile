# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG BASELINE_VERSION
ARG EXPECTED_VERSION
ARG APT_SOURCES_B64
ARG BINARY_PACKAGES
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
    apt-get install -y --no-install-recommends build-essential python3 valgrind pkg-config; \
    apt-get -y dist-upgrade; \
    for binary in $BINARY_PACKAGES; do \
      candidate="$(apt-cache policy "$binary" | awk '/Candidate:/ {print $2}')"; \
      test "$candidate" = "$BASELINE_VERSION" || { echo "Baseline candidate changed for $binary: $candidate" >&2; exit 1; }; \
    done; \
    for binary in $BINARY_PACKAGES; do apt-get install -y --no-install-recommends "$binary=$BASELINE_VERSION"; done
COPY getpatched/ /tmp/getpatched/
RUN set -eu; \
    test -n "$BINARY_PACKAGES"; \
    packages=""; \
    for binary in $BINARY_PACKAGES; do \
      package="$(find /tmp/getpatched -maxdepth 1 -name "${binary}_*.deb" -print -quit)"; \
      test -n "$package"; \
      packages="${packages}${packages:+ }$package"; \
    done; \
    apt-get install -y --no-install-recommends $packages; \
    for binary in $BINARY_PACKAGES; do \
      test "$(dpkg-query -W -f='${Version}' "$binary")" = "$EXPECTED_VERSION"; \
    done; \
    rm -rf /tmp/getpatched /var/lib/apt/lists/*
