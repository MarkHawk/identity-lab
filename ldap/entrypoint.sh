#!/usr/bin/env bash
# Start slapd. On first boot (empty volume) build cn=config and the directory
# from config.ldif and seed.ldif, like Keycloak's realm import: later changes
# live in the volume, and `scripts/test.sh --fresh` starts again from the LDIF.
#
# Secrets arrive in the environment from .env, are hashed with slappasswd
# reading stdin (never argv), and are unset before slapd starts.
set -euo pipefail

DATA=/var/lib/idlab-ldap
SRC=/etc/idlab/ldap

hash() { printf '%s' "$1" | slappasswd -h '{SSHA}' -T /dev/stdin; }

# render <file> -- print the file with ${NAME} placeholders replaced.
render() {
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//\$\{LDAP_ADMIN_PASSWORD_HASH\}/"$ADMIN_HASH"}"
    line="${line//\$\{LDAP_BIND_PASSWORD_HASH\}/"$BIND_HASH"}"
    line="${line//\$\{RADIUS_LDAP_BIND_PASSWORD_HASH\}/"$RADIUS_BIND_HASH"}"
    line="${line//\$\{DEMO_PASSWORD_HASH\}/"$DEMO_HASH"}"
    printf '%s\n' "$line"
  done <"$1"
}

if [[ ! -d "$DATA/config" ]]; then
  : "${LDAP_ADMIN_PASSWORD:?}" "${LDAP_BIND_PASSWORD:?}" "${RADIUS_LDAP_BIND_PASSWORD:?}" "${DEMO_PASSWORD:?}"
  echo "ldap: first boot, seeding dc=idlab,dc=example from $SRC"
  ADMIN_HASH="$(hash "$LDAP_ADMIN_PASSWORD")"
  BIND_HASH="$(hash "$LDAP_BIND_PASSWORD")"
  RADIUS_BIND_HASH="$(hash "$RADIUS_LDAP_BIND_PASSWORD")"
  DEMO_HASH="$(hash "$DEMO_PASSWORD")"
  # The mdb directory named in config.ldif must exist before config is
  # loaded. Config is moved into place last, so an interrupted seed is redone.
  tmp="$DATA/.seeding"
  rm -rf "$tmp" "$DATA/data"
  mkdir -p "$tmp/config" "$DATA/data"
  render "$SRC/config.ldif" | slapadd -q -n 0 -F "$tmp/config"
  render "$SRC/seed.ldif" | slapadd -q -n 1 -F "$tmp/config"
  mv "$tmp/config" "$DATA/config"
  rm -rf "$tmp"
  echo "ldap: seeded"
fi
unset LDAP_ADMIN_PASSWORD LDAP_BIND_PASSWORD RADIUS_LDAP_BIND_PASSWORD DEMO_PASSWORD

# -d 256 (stats): stay in the foreground and log every connection, BIND and
# RESULT to stderr, so a failed bind shows up as err=49 in compose logs.
exec slapd -d 256 -F "$DATA/config" -h "ldaps://:1636/"
