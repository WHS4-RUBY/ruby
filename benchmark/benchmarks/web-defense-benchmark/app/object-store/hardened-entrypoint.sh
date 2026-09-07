#!/bin/sh
set -eu

mkdir -p /data /logs
chown -R rustfs:rustfs /data /logs
exec su-exec rustfs:rustfs /entrypoint.sh "$@"
