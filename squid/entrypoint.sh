#!/usr/bin/env bash
# Start Squid in the foreground as LAB_UID (no root, no privileged port).
#
# EGRESS_PROXY_PASSWORD arrives from .env, is hashed with openssl reading
# stdin (never argv) into the file basic_ncsa_auth reads, and is unset
# before Squid starts. Squid only uses that file while proxy login is on
# (scenarios/proxy-auth-required.sh).
set -euo pipefail

: "${EGRESS_PROXY_PASSWORD:?}"
( umask 077
  printf 'egress-svc:%s\n' "$(printf '%s' "$EGRESS_PROXY_PASSWORD" | openssl passwd -apr1 -stdin)" \
    >/tmp/squid-passwd )
unset EGRESS_PROXY_PASSWORD

# Database of the certificates Squid mints when it intercepts TLS. Rebuilt
# on every start; it only caches.
rm -rf /tmp/ssl_db
/usr/local/squid/libexec/security_file_certgen -c -s /tmp/ssl_db -M 4MB >/dev/null

exec squid -N -f /etc/squid/squid.conf "$@"
