ARG BASE_IMAGE
ARG TRUST_IMAGE
FROM ${TRUST_IMAGE} AS trust
FROM ${BASE_IMAGE}
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ARG SOURCE_PACKAGE
ARG BASELINE_VERSION
ARG EXPECTED_VERSION
ARG ARCHIVE_SNAPSHOT
ARG BINARY_PACKAGES
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eu; \
    test -n "$ARCHIVE_SNAPSHOT"; \
    : > /etc/apt/sources.list; \
    for suite in focal focal-updates focal-security; do \
      printf 'deb https://snapshot.ubuntu.com/ubuntu/%s/ %s main universe restricted multiverse\n' "$ARCHIVE_SNAPSHOT" "$suite" >> /etc/apt/sources.list; \
    done; \
    apt-get update; \
    apt-get -y dist-upgrade; \
    case "$SOURCE_PACKAGE" in \
      libxml2) binaries="libxml2 libxml2-utils" ;; \
      libarchive) binaries="libarchive13 libarchive-tools" ;; \
      *) echo "Unsupported source package" >&2; exit 1 ;; \
    esac; \
    for binary in $binaries; do \
      candidate="$(apt-cache policy "$binary" | awk '/Candidate:/ {print $2}')"; \
      test "$candidate" = "$BASELINE_VERSION" || { echo "Baseline candidate changed for $binary: $candidate" >&2; exit 1; }; \
    done; \
    for binary in $binaries; do apt-get install -y --no-install-recommends "$binary=$BASELINE_VERSION"; done
COPY aptto/ /tmp/aptto/
RUN set -eu; \
    test -n "$BINARY_PACKAGES"; \
    for binary in $BINARY_PACKAGES; do \
      package="$(find /tmp/aptto -maxdepth 1 -name "${binary}_*.deb" -print -quit)"; \
      test -n "$package"; \
      apt-get install -y --no-install-recommends "$package"; \
      test "$(dpkg-query -W -f='${Version}' "$binary")" = "$EXPECTED_VERSION"; \
    done; \
    rm -rf /tmp/aptto /var/lib/apt/lists/*
