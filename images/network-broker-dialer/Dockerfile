# syntax=docker/dockerfile:1

ARG SOURCE_DATE_EPOCH

FROM debian:bookworm-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4 AS context-audit
COPY . /context
RUN set -eu; \
    find /context -mindepth 1 -print | while IFS= read -r candidate; do \
      relative=${candidate#/context/}; \
      case "$relative" in \
        Dockerfile|.dockerignore|build|build/portable-ghar-network-broker-dialer|build/portable-ghar-network-broker-parser|build/ca-bundle.pem|build/ca-bundle.sha256|build/ca-bundle.lock.json|build/ca-bundle.spdx.json) ;; \
        *) exit 1 ;; \
      esac; \
    done; \
    test -x /context/build/portable-ghar-network-broker-dialer; \
    test -x /context/build/portable-ghar-network-broker-parser; \
    cd /context/build; \
    sha256sum -c ca-bundle.sha256; \
    printf '%s\n' verified > /context-audit.OK

FROM debian:bookworm-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4 AS layout
RUN install -d -m 0755 /etc/ssl/certs /usr/share/portable-ghar && \
    install -d -m 0700 -o 65532 -g 65532 /run/portable-ghar/relay /run/portable-ghar/authority /run/portable-ghar/state /tmp

FROM scratch
COPY --from=context-audit --chown=0:0 --chmod=0444 /context-audit.OK /context-audit.OK
COPY --from=layout /etc/ssl/certs /etc/ssl/certs
COPY --from=layout /usr/share/portable-ghar /usr/share/portable-ghar
COPY --from=layout /run/portable-ghar /run/portable-ghar
COPY --from=layout /tmp /tmp
COPY --from=context-audit --chown=65532:65532 --chmod=0555 /context/build/portable-ghar-network-broker-dialer /usr/local/bin/portable-ghar-network-broker-dialer
COPY --from=context-audit --chown=65532:65532 --chmod=0555 /context/build/portable-ghar-network-broker-parser /usr/local/bin/portable-ghar-network-broker-parser
COPY --from=context-audit --chown=0:0 --chmod=0444 /context/build/ca-bundle.pem /etc/ssl/certs/ca-bundle.crt
COPY --from=context-audit --chown=0:0 --chmod=0444 /context/build/ca-bundle.lock.json /usr/share/portable-ghar/ca-bundle.lock.json
COPY --from=context-audit --chown=0:0 --chmod=0444 /context/build/ca-bundle.spdx.json /usr/share/portable-ghar/ca-bundle.spdx.json
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/portable-ghar-network-broker-dialer"]
CMD ["hold"]
