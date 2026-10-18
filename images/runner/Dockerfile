# syntax=docker/dockerfile:1

ARG SOURCE_DATE_EPOCH

FROM scratch AS debian-cache

FROM debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867 AS context-audit
RUN --mount=type=bind,source=.,target=/context,ro set -eu; \
    find /context -mindepth 1 -print | while IFS= read -r candidate; do \
      relative=${candidate#/context/}; \
      case "$relative" in \
        Dockerfile|.dockerignore|build| \
        build/portable-ghar-runner-gate| \
        build/runner|build/runner/*| \
        build/runner.tree-manifest.json|build/runner.tree-lock| \
        build/runner.runtime-lock.json|build/runner.READY| \
        build/seed-cache|build/seed-cache/*| \
        build/seed-cache.manifest.json|build/seed-cache.tree-lock| \
        build/seed-cache.READY| \
        build/ca-bundle.pem|build/ca-bundle.lock.json|build/ca-bundle.sha256) ;; \
        *) exit 1 ;; \
      esac; \
    done; \
    expected_ca_sha=3ff344e30b9b1ed2971044eabb438a08f2e2245ddb5f8ab1a3ad8b63ab4eaf91; \
    expected_ca_lock_sha=b39d26752fd97766b533547ff731334348c0f35e041adb49848e2cd10f30c592; \
    test "$(sha256sum /context/build/ca-bundle.lock.json | awk '{print $1}')" = "$expected_ca_lock_sha"; \
    test "$(sha256sum /context/build/ca-bundle.pem | awk '{print $1}')" = "$expected_ca_sha"; \
    cd /context/build; \
    printf '%s  %s\n' "$expected_ca_sha" ca-bundle.pem | cmp - ca-bundle.sha256; \
    sha256sum -c ca-bundle.sha256; \
    test -x /context/build/portable-ghar-runner-gate; \
    test -f /context/build/runner.READY; \
    test -f /context/build/seed-cache.READY; \
    cp /context/build/ca-bundle.pem /verified-ca-bundle.pem; \
    printf '%s\n' verified > /context-audit.OK

FROM debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867
ARG SOURCE_DATE_EPOCH
ARG DEBIAN_SNAPSHOT_SOURCE=network
COPY --from=context-audit --chown=0:0 --chmod=0444 /verified-ca-bundle.pem /portable-ghar-bootstrap-ca.pem
RUN --mount=type=bind,from=debian-cache,target=/snapshot-cache,ro \
    --mount=type=bind,source=build,target=/inputs,ro \
    --mount=type=bind,from=context-audit,source=/context-audit.OK,target=/context-audit.OK,ro \
    set -eu; \
    case "${SOURCE_DATE_EPOCH:-}" in \
      ""|*[!0-9]*) exit 1 ;; \
    esac; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    snapshot=20261010T000000Z; \
    case "$DEBIAN_SNAPSHOT_SOURCE" in \
      network) \
        printf '%s\n' \
          "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${snapshot} bookworm main" \
          "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${snapshot} bookworm-updates main" \
          "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${snapshot} bookworm-security main" \
          > /etc/apt/sources.list ;; \
      offline) \
        printf '%s\n' \
          "deb [check-valid-until=no] file:/snapshot-cache/archive/debian/${snapshot} bookworm main" \
          "deb [check-valid-until=no] file:/snapshot-cache/archive/debian/${snapshot} bookworm-updates main" \
          "deb [check-valid-until=no] file:/snapshot-cache/archive/debian-security/${snapshot} bookworm-security main" \
          > /etc/apt/sources.list ;; \
      *) exit 1 ;; \
    esac; \
    apt-get \
      -o Acquire::Check-Valid-Until=false \
      -o Acquire::Languages=none \
      -o Acquire::By-Hash=false \
      -o Acquire::https::CaInfo=/portable-ghar-bootstrap-ca.pem \
      -o Acquire::https::Verify-Peer=true \
      -o Acquire::https::Verify-Host=true \
      update \
    && apt-get \
      -o Acquire::https::CaInfo=/portable-ghar-bootstrap-ca.pem \
      -o Acquire::https::Verify-Peer=true \
      -o Acquire::https::Verify-Host=true \
      install -y --no-install-recommends \
      ca-certificates curl git libicu72 libkrb5-3 liblttng-ust1 libssl3 zlib1g \
    && apt-get \
      -o Acquire::https::CaInfo=/portable-ghar-bootstrap-ca.pem \
      -o Acquire::https::Verify-Peer=true \
      -o Acquire::https::Verify-Host=true \
      dist-upgrade -y --no-install-recommends \
    && install -d -m 0755 /usr/share/portable-ghar \
    && dpkg-query -W -f='${Package}\t${Version}\n' \
      | LC_ALL=C sort > /usr/share/portable-ghar/dpkg-manifest.tsv \
    && chmod 0444 /usr/share/portable-ghar/dpkg-manifest.tsv \
    && rm -rf \
      /var/cache/apt/* \
      /var/lib/apt/lists/* \
      /var/log/apt/* \
    && rm -f \
      /var/cache/ldconfig/aux-cache \
      /var/log/alternatives.log \
      /var/log/dpkg.log \
    && sed -i 's|file:/snapshot-cache/archive/|https://snapshot.debian.org/archive/|g' /etc/apt/sources.list \
    && rm -f /portable-ghar-bootstrap-ca.pem \
    && install -d -m 0755 /opt/portable-ghar /usr/local/bin \
    && cp -Rp /inputs/seed-cache /opt/portable-ghar/seed-cache \
    && install -m 0444 /context-audit.OK /opt/portable-ghar/context-audit.OK \
    && install -m 0444 /inputs/runner.tree-manifest.json /inputs/runner.tree-lock /inputs/runner.runtime-lock.json /inputs/runner.READY /inputs/seed-cache.manifest.json /inputs/seed-cache.tree-lock /inputs/seed-cache.READY /opt/portable-ghar/ \
    && install -m 0555 /inputs/portable-ghar-runner-gate /usr/local/bin/portable-ghar-runner-gate
COPY --chown=0:0 build/runner /opt/actions-runner
RUN chmod 0555 /opt/actions-runner /opt/portable-ghar/seed-cache \
    && expected_version=$(/usr/local/bin/portable-ghar-runner-gate verify-image) \
    && installed_version=$(/opt/actions-runner/bin/Runner.Listener --version) \
    && test "$installed_version" = "$expected_version" \
    && rm -rf /opt/actions-runner/_diag \
    && test ! -e /opt/actions-runner/_diag \
    && test "$(/usr/local/bin/portable-ghar-runner-gate verify-image)" = "$expected_version" \
    && ln -s /runner/_diag /opt/actions-runner/_diag \
    && ln -s /runner/_work /opt/actions-runner/_work \
    && ln -s /runner/.runner /opt/actions-runner/.runner \
    && ln -s /runner/.credentials /opt/actions-runner/.credentials \
    && ln -s /runner/.credentials_rsaparams /opt/actions-runner/.credentials_rsaparams \
    && /usr/local/bin/portable-ghar-runner-gate verify-image-overlay \
    && test ! -e /portable-ghar-bootstrap-ca.pem \
    && test -r /usr/share/portable-ghar/dpkg-manifest.tsv \
    && install -d -m 0700 -o 65532 -g 65532 /runner /tmp /scratch \
    && rm -rf /root

ENV HOME=/runner \
    LANG=C.UTF-8 \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/portable-ghar-runner-gate"]
CMD ["hold"]
