ARG BASE_IMAGE
ARG TRUST_IMAGE
FROM ${TRUST_IMAGE} AS trust
FROM ${BASE_IMAGE}
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ARG SOURCE_PACKAGE
ARG BASELINE_VERSION
ARG EXPECTED_VERSION
ARG APT_SOURCES_B64
ARG BINARY_PACKAGES
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eu; \
    test -n "$APT_SOURCES_B64"; \
    printf '%s' "$APT_SOURCES_B64" | base64 -d > /etc/apt/sources.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends build-essential python3 valgrind; \
    apt-get -y dist-upgrade; \
    case "$SOURCE_PACKAGE" in \
      libxml2) binaries="libxml2 libxml2-utils" ;; \
      libarchive) binaries="libarchive13 libarchive-tools" ;; \
      libpng1.6) binaries="libpng16-16 libpng-dev libpng-tools" ;; \
      libgit2) binaries="libgit2-28 libgit2-dev" ;; \
      poppler) binaries="libpoppler97 libpoppler-dev libpoppler-private-dev libpoppler-glib8 libpoppler-glib-dev libpoppler-glib-doc gir1.2-poppler-0.18 libpoppler-qt5-1 libpoppler-qt5-dev libpoppler-cpp0v5 libpoppler-cpp-dev poppler-utils" ;; \
      tiff) binaries="libtiff-tools" ;; \
      *) echo "Unsupported source package" >&2; exit 1 ;; \
    esac; \
    for binary in $binaries; do \
      candidate="$(apt-cache policy "$binary" | awk '/Candidate:/ {print $2}')"; \
      test "$candidate" = "$BASELINE_VERSION" || { echo "Baseline candidate changed for $binary: $candidate" >&2; exit 1; }; \
    done; \
    for binary in $binaries; do apt-get install -y --no-install-recommends "$binary=$BASELINE_VERSION"; done
COPY getpatched/ /tmp/getpatched/
RUN set -eu; \
    test -n "$BINARY_PACKAGES"; \
    for binary in $BINARY_PACKAGES; do \
      package="$(find /tmp/getpatched -maxdepth 1 -name "${binary}_*.deb" -print -quit)"; \
      test -n "$package"; \
      apt-get install -y --no-install-recommends "$package"; \
      test "$(dpkg-query -W -f='${Version}' "$binary")" = "$EXPECTED_VERSION"; \
    done; \
    rm -rf /tmp/getpatched /var/lib/apt/lists/*
