ARG BASE_IMAGE
ARG TRUST_IMAGE
FROM ${TRUST_IMAGE} AS trust
FROM ${BASE_IMAGE}
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ARG SOURCE_PACKAGE
ARG EXPECTED_VERSION
ARG ARCHIVE_SNAPSHOT
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eu; \
    test -n "$ARCHIVE_SNAPSHOT"; \
    apt_get() { apt-get -o Acquire::Retries=3 "$@"; }; \
    : > /etc/apt/sources.list; \
    for suite in focal focal-updates focal-security; do \
      printf 'deb https://snapshot.ubuntu.com/ubuntu/%s/ %s main universe restricted multiverse\n' "$ARCHIVE_SNAPSHOT" "$suite" >> /etc/apt/sources.list; \
      printf 'deb-src https://snapshot.ubuntu.com/ubuntu/%s/ %s main universe restricted multiverse\n' "$ARCHIVE_SNAPSHOT" "$suite" >> /etc/apt/sources.list; \
    done; \
    case "$SOURCE_PACKAGE" in \
      libxml2) binaries="libxml2 libxml2-utils libxml2-dev" ;; \
      libarchive) binaries="libarchive13 libarchive-tools libarchive-dev" ;; \
      *) exit 1 ;; \
    esac; \
    attempt=0; \
    until { apt_get update > /tmp/apt-update.log 2>&1 && ! grep -Eq '^(Err:|W: Failed to fetch|E: Some index files failed to download)' /tmp/apt-update.log; }; do \
      cat /tmp/apt-update.log; \
      attempt=$((attempt + 1)); \
      if [ "$attempt" -ge 3 ]; then exit 1; fi; \
      sleep $((attempt * 10)); \
      rm -rf /var/lib/apt/lists/*; \
    done; \
    cat /tmp/apt-update.log; \
    apt_get -y dist-upgrade; \
    for binary in $binaries; do \
      test "$(apt-cache policy "$binary" | awk '/Candidate:/ {print $2}')" = "$EXPECTED_VERSION"; \
    done; \
    apt_get install -y --no-install-recommends build-essential fakeroot dpkg-dev apt-utils gnupg python3 valgrind pkg-config; \
    apt_get build-dep -y --no-install-recommends "$SOURCE_PACKAGE"; \
    for binary in $binaries; do apt_get install -y --no-install-recommends "$binary=$EXPECTED_VERSION"; done; \
    rm -rf /var/lib/apt/lists/*
