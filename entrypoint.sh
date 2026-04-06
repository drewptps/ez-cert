#!/bin/sh
set -e

# Fix data directory ownership in case a host volume was mounted as root
chown -R ezcert:ezcert /app/data

exec su-exec ezcert ./ez-cert "$@"
