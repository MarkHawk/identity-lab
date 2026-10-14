#!/usr/bin/env bash
# Store the NAS's copy of the RADIUS shared secret on first boot, like
# typing it into a switch once at install time. Later changes (for example
# scenarios/radius-shared-secret-mismatch.sh) live in the volume, and
# `scripts/test.sh --fresh` starts again from .env.
set -euo pipefail

SECRET_FILE=/var/lib/nas/secret

if [[ ! -s "$SECRET_FILE" ]]; then
  : "${RADIUS_SECRET:?}"
  ( umask 077; printf '%s' "$RADIUS_SECRET" >"$SECRET_FILE.tmp" )
  mv "$SECRET_FILE.tmp" "$SECRET_FILE"
  echo "nas: stored the RADIUS shared secret"
fi
unset RADIUS_SECRET

# Nothing to serve: the NAS only sends requests, via nas-auth.
exec sleep infinity
