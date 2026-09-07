FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

RUN apk upgrade --no-cache \
    && apk add --no-cache \
        postgresql17=17.11-r0 \
        postgresql17-client=17.11-r0 \
        su-exec=0.3-r0 \
    && rm -rf /var/cache/apk/*

ENV PGDATA=/var/lib/postgresql/data
COPY entrypoint.sh /usr/local/bin/ruby-postgres-entrypoint
RUN chmod 0755 /usr/local/bin/ruby-postgres-entrypoint \
    && mkdir -p /var/lib/postgresql/data /run/postgresql \
    && chown -R postgres:postgres /var/lib/postgresql /run/postgresql

ENTRYPOINT ["/usr/local/bin/ruby-postgres-entrypoint"]
CMD ["postgres"]
