FROM rustfs/rustfs:latest@sha256:41fe89380f4120a337790c02af192c3fe7bb55c3edc2e6e9357b487b47c6ab21

USER root
RUN apk update \
    && apk upgrade --no-cache \
    && apk add --no-cache su-exec \
    && rm -rf /var/cache/apk/*
COPY hardened-entrypoint.sh /usr/local/bin/hardened-entrypoint.sh
RUN chmod 0755 /usr/local/bin/hardened-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/hardened-entrypoint.sh"]
