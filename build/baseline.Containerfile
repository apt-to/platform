ARG BASE_IMAGE
ARG TRUST_IMAGE
FROM ${TRUST_IMAGE} AS trust
FROM ${BASE_IMAGE}
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ARG SOURCE_PACKAGE
ARG EXPECTED_VERSION
ARG APT_SOURCES_B64
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eu; \
    test -n "$APT_SOURCES_B64"; \
    printf '%s' "$APT_SOURCES_B64" | base64 -d > /etc/apt/sources.list; \
    case "$SOURCE_PACKAGE" in \
      libxml2) binaries="libxml2 libxml2-utils" ;; \
      libarchive) binaries="libarchive13 libarchive-tools" ;; \
      *) echo "Unsupported source package" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get -y dist-upgrade; \
    for binary in $binaries; do \
      candidate="$(apt-cache policy "$binary" | awk '/Candidate:/ {print $2}')"; \
      test "$candidate" = "$EXPECTED_VERSION" || { \
        echo "Public candidate changed for $binary: $candidate (expected $EXPECTED_VERSION); refresh preflight, do not downgrade." >&2; \
        exit 1; \
      }; \
    done; \
    for binary in $binaries; do apt-get install -y --no-install-recommends "$binary=$EXPECTED_VERSION"; done; \
    dpkg-query -W libxml2 libarchive13 2>/dev/null || true; \
    rm -rf /var/lib/apt/lists/*
