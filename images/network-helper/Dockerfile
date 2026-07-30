# syntax=docker/dockerfile:1

ARG SOURCE_DATE_EPOCH

FROM debian:bookworm-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4 AS context-audit
COPY . /context
RUN set -eu; \
    find /context -mindepth 1 -print | while IFS= read -r candidate; do \
      relative=${candidate#/context/}; \
      case "$relative" in \
        Dockerfile|.dockerignore|build|build/portable-ghar-network-helper|build/rootfs|build/rootfs/*|build/legacy.layout|build/legacy.layout.sha256|build/legacy.sha256|build/legacy.manifest.json|build/packages.lock.json|build/packages.spdx.json) ;; \
        *) exit 1 ;; \
      esac; \
    done; \
    test -x /context/build/portable-ghar-network-helper; \
    test -f /context/build/legacy.layout; \
    test -f /context/build/legacy.layout.sha256; \
    test -f /context/build/legacy.sha256; \
    test -f /context/build/legacy.manifest.json; \
    test -f /context/build/packages.lock.json; \
    test -f /context/build/packages.spdx.json; \
    cd /context/build/rootfs; \
    sha256sum -c ../legacy.sha256; \
    actual=$(find . -mindepth 1 -printf '%y %m %P %l\n' | LC_ALL=C sort | sha256sum | cut -d' ' -f1); \
    expected=$(cut -d' ' -f1 ../legacy.layout.sha256); \
    test "$actual" = "$expected"; \
    printf '%s\n' verified > /context-audit.OK

FROM scratch
COPY --from=context-audit --chown=0:0 --chmod=0444 /context-audit.OK /context-audit.OK
COPY --from=context-audit /context/build/rootfs /
COPY --from=context-audit --chown=0:0 --chmod=0555 /context/build/portable-ghar-network-helper /usr/local/bin/portable-ghar-network-helper
COPY --from=context-audit --chown=0:0 --chmod=0444 /context/build/legacy.manifest.json /usr/share/portable-ghar/legacy.manifest.json
COPY --from=context-audit --chown=0:0 --chmod=0444 /context/build/packages.lock.json /usr/share/portable-ghar/packages.lock.json
COPY --from=context-audit --chown=0:0 --chmod=0444 /context/build/packages.spdx.json /usr/share/portable-ghar/packages.spdx.json
ENTRYPOINT ["/usr/local/bin/portable-ghar-network-helper"]
CMD ["apply"]
