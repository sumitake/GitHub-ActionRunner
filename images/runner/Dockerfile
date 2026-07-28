# syntax=docker/dockerfile:1

FROM debian:bookworm-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4 AS context-audit
COPY . /context
RUN set -eu; \
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
        build/seed-cache.READY) ;; \
        *) exit 1 ;; \
      esac; \
    done; \
    test -x /context/build/portable-ghar-runner-gate; \
    test -f /context/build/runner.READY; \
    test -f /context/build/seed-cache.READY; \
    printf '%s\n' verified > /context-audit.OK

FROM debian:bookworm-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      libicu72 \
      libkrb5-3 \
      liblttng-ust1 \
      libssl3 \
      zlib1g \
    && rm -rf /var/lib/apt/lists/*
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
    && install -d -m 0700 -o 65532 -g 65532 /runner /tmp /scratch

ENV HOME=/runner \
    LANG=C.UTF-8 \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/portable-ghar-runner-gate"]
CMD ["hold"]
