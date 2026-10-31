# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG SOURCE_PACKAGE
ARG EXPECTED_VERSION
ARG BINARY_PACKAGES
ARG BUILDER_PACKAGES
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
    install_packages="$BINARY_PACKAGES $BUILDER_PACKAGES"; \
    apt_get() { apt-get -o Acquire::Retries=3 -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false "$@"; }; \
    apt_retry() { attempt=0; until apt_get "$@"; do attempt=$((attempt + 1)); if [ "$attempt" -ge 3 ]; then return 1; fi; sleep $((attempt * 10)); done; }; \
    printf '%s' "$APT_SOURCES_B64" | base64 -d > /etc/apt/sources.list; \
    attempt=0; \
    until { apt_get update > /tmp/apt-update.log 2>&1 && ! grep -Eq '^(Err:|W: Failed to fetch|E: Some index files failed to download)' /tmp/apt-update.log; }; do \
      cat /tmp/apt-update.log; \
      attempt=$((attempt + 1)); \
      if [ "$attempt" -ge 3 ]; then exit 1; fi; \
      sleep $((attempt * 10)); \
      rm -rf /var/lib/apt/lists/*; \
    done; \
    cat /tmp/apt-update.log; \
    apt_retry -y dist-upgrade; \
    for binary in $install_packages; do \
      test "$(apt-cache policy "$binary" | awk '/Candidate:/ {print $2}')" = "$EXPECTED_VERSION"; \
    done; \
    apt_retry install -y --no-install-recommends build-essential fakeroot dpkg-dev apt-utils gnupg python3 valgrind pkg-config; \
    apt_retry build-dep -y --no-install-recommends "$SOURCE_PACKAGE"; \
    for binary in $install_packages; do apt_retry install -y --no-install-recommends "$binary=$EXPECTED_VERSION"; done; \
    rm -rf /var/lib/apt/lists/*
