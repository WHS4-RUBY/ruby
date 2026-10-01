#!/bin/sh
set -eu

public_name=${RUBY_PUBLIC_NAME:-juice-shop}
forwarded_proto=${RUBY_FORWARDED_PROTO:-http}

if ! printf '%s' "$public_name" | grep -Eq '^[a-z][a-z0-9-]{0,39}$'; then
    echo 'RUBY_PUBLIC_NAME must be a lowercase URL name (1-40 characters)' >&2
    exit 1
fi
case "$public_name" in
    api|assets|rest|healthz|__detection|__defense)
        echo 'RUBY_PUBLIC_NAME conflicts with a reserved root path' >&2
        exit 1
        ;;
esac
case "$forwarded_proto" in
    http|https) ;;
    *) echo 'RUBY_FORWARDED_PROTO must be http or https' >&2; exit 1 ;;
esac

sed \
    -e "s/@PUBLIC_NAME@/$public_name/g" \
    -e "s/@FORWARDED_PROTO@/$forwarded_proto/g" \
    /etc/nginx/ruby/default.conf.template > /etc/nginx/conf.d/default.conf

nginx -t
exec nginx -g 'daemon off;'
