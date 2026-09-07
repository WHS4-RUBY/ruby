FROM redis:8-alpine3.23@sha256:becdda6c7f4b3fb42e42fd7f120bbf5c54c4caaaf16f26da24e4563d2c1f0576

RUN apk upgrade --no-cache \
    && rm -rf /var/cache/apk/*
USER redis
