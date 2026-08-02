# syntax=docker/dockerfile:1

ARG SOURCE_DATE_EPOCH

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS context-audit
COPY . /context
RUN set -eu; \
    find /context -mindepth 1 -print | while IFS= read -r candidate; do \
      relative=${candidate#/context/}; \
      case "$relative" in \
        Dockerfile|.dockerignore|build|build/portable-ghar-network-broker-parser) ;; \
        *) exit 1 ;; \
      esac; \
    done; \
    test -x /context/build/portable-ghar-network-broker-parser; \
    printf '%s\n' verified > /context-audit.OK

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS layout
RUN install -d -m 0700 -o 65532 -g 65532 /run/portable-ghar/relay /run/portable-ghar/state /tmp

FROM scratch
COPY --from=context-audit --chown=0:0 --chmod=0444 /context-audit.OK /context-audit.OK
COPY --from=context-audit --chown=65532:65532 --chmod=0555 /context/build/portable-ghar-network-broker-parser /usr/local/bin/portable-ghar-network-broker-parser
COPY --from=layout /run/portable-ghar /run/portable-ghar
COPY --from=layout /tmp /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/portable-ghar-network-broker-parser"]
CMD ["serve"]
