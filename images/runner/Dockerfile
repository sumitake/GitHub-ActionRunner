# syntax=docker/dockerfile:1

ARG SOURCE_DATE_EPOCH

FROM debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867 AS context-audit
COPY . /context
RUN set -eu; \
    find /context -mindepth 1 -print | while IFS= read -r candidate; do \
      relative=${candidate#/context/}; \
      case "$relative" in \
        Dockerfile|.dockerignore|debian-snapshot.lock.json|verify-debian-snapshot.sh|build| \
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
    expected_debian_snapshot_lock_sha=9448eec7f0584d18d4ad5b01800758a26e8eba197dd3f2646ef87febbfe78e03; \
    test "$(sha256sum /context/build/ca-bundle.lock.json | awk '{print $1}')" = "$expected_ca_lock_sha"; \
    test "$(sha256sum /context/build/ca-bundle.pem | awk '{print $1}')" = "$expected_ca_sha"; \
    test "$(sha256sum /context/debian-snapshot.lock.json | awk '{print $1}')" = "$expected_debian_snapshot_lock_sha"; \
    test -x /context/verify-debian-snapshot.sh; \
    sh -n /context/verify-debian-snapshot.sh; \
    cd /context/build; \
    printf '%s  %s\n' "$expected_ca_sha" ca-bundle.pem | cmp - ca-bundle.sha256; \
    sha256sum -c ca-bundle.sha256; \
    test -x /context/build/portable-ghar-runner-gate; \
    test -f /context/build/runner.READY; \
    test -f /context/build/seed-cache.READY; \
    printf '%s\n' verified > /context-audit.OK

FROM debian:bookworm-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867
ARG SOURCE_DATE_EPOCH
COPY --from=context-audit --chown=0:0 --chmod=0444 /context/build/ca-bundle.pem /portable-ghar-bootstrap-ca.pem
COPY --from=context-audit --chown=0:0 --chmod=0444 /context/debian-snapshot.lock.json /usr/share/portable-ghar/debian-snapshot.lock.json
COPY --from=context-audit --chown=0:0 --chmod=0555 /context/verify-debian-snapshot.sh /usr/local/bin/verify-debian-snapshot
RUN set -eu; \
    case "${SOURCE_DATE_EPOCH:-}" in \
      ""|*[!0-9]*) exit 1 ;; \
    esac; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    printf '%s\n' \
      'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260824T000000Z bookworm main' \
      'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260824T000000Z bookworm-updates main' \
      'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20260906T000000Z bookworm-security main' \
      > /etc/apt/sources.list; \
    apt-get \
      -o Acquire::Check-Valid-Until=false \
      -o Acquire::https::CaInfo=/portable-ghar-bootstrap-ca.pem \
      -o Acquire::https::Verify-Peer=true \
      -o Acquire::https::Verify-Host=true \
      update \
    && /usr/local/bin/verify-debian-snapshot /var/lib/apt/lists \
      bookworm 77737fa4b34f2693e982cc9ee35736816c35a7778fc2d326cc1bbf5b301fe1aa 8790396 9e0b5aabb2465b3d2e7a7fe27f9913846277833f7a2826e7767acccff5b588c5 \
      bookworm-updates c41bb7c5ad6a952234e53ec0c81099459e8c2d58adbeb5bf797ec29863451ab0 6924 87e7e94047fb7fb6f4ceecc7022d4bee55b66031cc2a7666d3196f3e0aabb846 \
      bookworm-security 54fbb49bee8e9b916e702b754081ab2c292038c477d0c1dbe7a09f4b753ed828 336508 904649be6031840086ed21432f83c0c85941ff5d57169100d7d80e2becb1591c \
    && apt-get \
      -o Acquire::https::CaInfo=/portable-ghar-bootstrap-ca.pem \
      -o Acquire::https::Verify-Peer=true \
      -o Acquire::https::Verify-Host=true \
      install -y --no-install-recommends \
      ca-certificates=20230311+deb12u1 \
      curl=7.88.1-10+deb12u15 \
      git=1:2.39.5-0+deb12u3 \
      libicu72=72.1-3+deb12u1 \
      libkrb5-3=1.20.1-2+deb12u5 \
      liblttng-ust1=2.13.5-1 \
      libpcre2-8-0=10.42-1+deb12u1 \
      libssh2-1=1.10.0-3+deb12u1 \
      libssl3=3.0.20-1~deb12u2 \
      zlib1g=1:1.2.13.dfsg-1 \
    && printf '%s\t%s\n' \
      'ca-certificates' '20230311+deb12u1' \
      'curl' '7.88.1-10+deb12u15' \
      'git' '1:2.39.5-0+deb12u3' \
      'libicu72' '72.1-3+deb12u1' \
      'libkrb5-3' '1.20.1-2+deb12u5' \
      'liblttng-ust1' '2.13.5-1' \
      'libpcre2-8-0' '10.42-1+deb12u1' \
      'libssh2-1' '1.10.0-3+deb12u1' \
      'libssl3' '3.0.20-1~deb12u2' \
      'zlib1g' '1:1.2.13.dfsg-1' \
      'perl' '5.36.0-7+deb12u3' \
      'perl-base' '5.36.0-7+deb12u3' \
      | LC_ALL=C sort > /tmp/runner-package-anchors.expected \
    && for package in ca-certificates curl git libicu72 libkrb5-3 liblttng-ust1 libpcre2-8-0 libssh2-1 libssl3 zlib1g perl perl-base; do \
      dpkg-query -W -f='${Package}\t${Version}\n' "$package"; \
    done | LC_ALL=C sort > /usr/share/portable-ghar/runner-package-anchors.tsv \
    && cmp /tmp/runner-package-anchors.expected /usr/share/portable-ghar/runner-package-anchors.tsv \
    && dpkg-query -W -f='${Package}\t${Version}\n' \
      | LC_ALL=C sort > /usr/share/portable-ghar/dpkg-manifest.tsv \
    && chmod 0444 \
      /usr/share/portable-ghar/debian-snapshot.lock.json \
      /usr/share/portable-ghar/runner-package-anchors.tsv \
      /usr/share/portable-ghar/dpkg-manifest.tsv \
    && rm -rf \
      /var/cache/apt/* \
      /var/lib/apt/lists/* \
      /var/log/apt/* \
      /tmp/runner-package-anchors.expected \
    && rm -f \
      /var/cache/ldconfig/aux-cache \
      /var/log/alternatives.log \
      /var/log/dpkg.log \
    && rm -f /portable-ghar-bootstrap-ca.pem
COPY --from=context-audit --chown=0:0 --chmod=0444 /context-audit.OK /opt/portable-ghar/context-audit.OK
COPY --chown=0:0 build/runner /opt/actions-runner
COPY --chown=0:0 build/seed-cache /opt/portable-ghar/seed-cache
COPY --chown=0:0 --chmod=0444 build/runner.tree-manifest.json /opt/portable-ghar/runner.tree-manifest.json
COPY --chown=0:0 --chmod=0444 build/runner.tree-lock /opt/portable-ghar/runner.tree-lock
COPY --chown=0:0 --chmod=0444 build/runner.runtime-lock.json /opt/portable-ghar/runner.runtime-lock.json
COPY --chown=0:0 --chmod=0444 build/runner.READY /opt/portable-ghar/runner.READY
COPY --chown=0:0 --chmod=0444 build/seed-cache.manifest.json /opt/portable-ghar/seed-cache.manifest.json
COPY --chown=0:0 --chmod=0444 build/seed-cache.tree-lock /opt/portable-ghar/seed-cache.tree-lock
COPY --chown=0:0 --chmod=0444 build/seed-cache.READY /opt/portable-ghar/seed-cache.READY
COPY --chown=0:0 --chmod=0555 build/portable-ghar-runner-gate /usr/local/bin/portable-ghar-runner-gate
RUN chmod 0555 /opt/actions-runner /opt/portable-ghar/seed-cache \
    && expected_version=$(/usr/local/bin/portable-ghar-runner-gate verify-image) \
    && installed_version=$(/opt/actions-runner/bin/Runner.Listener --version) \
    && test "$installed_version" = "$expected_version" \
    && rm -rf /opt/actions-runner/_diag \
    && test ! -e /opt/actions-runner/_diag \
    && test "$(/usr/local/bin/portable-ghar-runner-gate verify-image)" = "$expected_version" \
    && ln -s /runner/_diag /opt/actions-runner/_diag \
    && ln -s /runner/_work /opt/actions-runner/_work \
    && /usr/local/bin/portable-ghar-runner-gate verify-image-overlay \
    && test ! -e /portable-ghar-bootstrap-ca.pem \
    && test -r /usr/share/portable-ghar/debian-snapshot.lock.json \
    && test -r /usr/share/portable-ghar/runner-package-anchors.tsv \
    && test -r /usr/share/portable-ghar/dpkg-manifest.tsv \
    && install -d -m 0700 -o 65532 -g 65532 /runner /tmp /scratch

ENV HOME=/runner \
    LANG=C.UTF-8 \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/portable-ghar-runner-gate"]
CMD ["hold"]
