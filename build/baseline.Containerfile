# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG SOURCE_PACKAGE
ARG EXPECTED_VERSION
ARG APT_SOURCES_B64
ENV DEBIAN_FRONTEND=noninteractive
RUN --mount=type=secret,id=runner-ca,target=/tmp/getpatched-runner-ca.crt,required=true \
    set -eu; \
    mkdir -p /etc/ssl/certs; \
    cp /tmp/getpatched-runner-ca.crt /etc/ssl/certs/ca-certificates.crt; \
    printf 'Acquire::https::CAInfo "/etc/ssl/certs/ca-certificates.crt";\n' > /etc/apt/apt.conf.d/99getpatched-ca; \
    test -n "$APT_SOURCES_B64"; \
    printf '%s' "$APT_SOURCES_B64" | base64 -d > /etc/apt/sources.list; \
    case "$SOURCE_PACKAGE" in \
      libxml2) binaries="libxml2 libxml2-utils" ;; \
      libarchive) binaries="libarchive13 libarchive-tools" ;; \
      libpng1.6) binaries="libpng16-16 libpng-dev libpng-tools" ;; \
      libgit2) binaries="libgit2-28 libgit2-dev" ;; \
      poppler) binaries="libpoppler97 libpoppler-dev libpoppler-private-dev libpoppler-glib8 libpoppler-glib-dev libpoppler-glib-doc gir1.2-poppler-0.18 libpoppler-qt5-1 libpoppler-qt5-dev libpoppler-cpp0v5 libpoppler-cpp-dev poppler-utils" ;; \
      tiff) binaries="libtiff-tools" ;; \
      *) echo "Unsupported source package" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get -y dist-upgrade; \
    apt-get install -y --no-install-recommends build-essential python3 valgrind pkg-config; \
    for binary in $binaries; do \
      candidate="$(apt-cache policy "$binary" | awk '/Candidate:/ {print $2}')"; \
      test "$candidate" = "$EXPECTED_VERSION" || { \
        echo "Public candidate changed for $binary: $candidate (expected $EXPECTED_VERSION); refresh preflight, do not downgrade." >&2; \
        exit 1; \
      }; \
    done; \
    for binary in $binaries; do apt-get install -y --no-install-recommends "$binary=$EXPECTED_VERSION"; done; \
    dpkg-query -W libxml2 libarchive13 libpng16-16 libpng-dev libpng-tools libgit2-28 libgit2-dev libtiff-tools libpoppler97 poppler-utils 2>/dev/null || true; \
    rm -rf /var/lib/apt/lists/*
