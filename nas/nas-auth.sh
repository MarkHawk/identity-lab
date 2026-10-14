#!/usr/bin/env bash
# Send one PAP Access-Request to the lab's RADIUS server, as a NAS does when
# a user logs in, and print the outcome.
#
#   nas-auth <user>                       prompts for the password (hidden)
#   printf '%s' "$pw" | nas-auth <user>   reads it from stdin
#
# radclient (3.2.10) always adds Message-Authenticator, as a current NAS does.
#
# The shared secret comes from the NAS's own file and the password from
# stdin: neither is ever on a command line or printed.
# Exit status: 0 Access-Accept, 1 Access-Reject, 2 no reply or other error.
set -euo pipefail

SECRET_FILE=/var/lib/nas/secret
SERVER="${NAS_RADIUS_SERVER:-radius:1812}"
TIMEOUT=2 TRIES=3   # like a typical NAS: 3 attempts, 2 seconds apart

[[ $# -eq 1 && "$1" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "usage: nas-auth <user>" >&2; exit 2; }
user="$1"
[[ -s "$SECRET_FILE" ]] || { echo "nas-auth: no shared secret in $SECRET_FILE" >&2; exit 2; }

if [[ -t 0 ]]; then
  read -r -s -p "Password for $user: " password; echo
else
  IFS= read -r password || [[ -n "$password" ]]
fi

# Attribute values in radclient's input are double-quoted strings.
esc() { local v="${1//\\/\\\\}"; printf '%s' "${v//\"/\\\"}"; }

request() {
  printf 'User-Name = "%s"\nUser-Password = "%s"\nNAS-Identifier = "nas"\nMessage-Authenticator = 0x00\n' \
    "$(esc "$user")" "$(esc "$password")"
}

echo "nas: Access-Request for $user to $SERVER"
out="$(request | radclient -r "$TRIES" -t "$TIMEOUT" -S "$SECRET_FILE" "$SERVER" auth 2>&1)" || true
unset password

case "$out" in
  *"Received Access-Accept"*) echo "nas: Access-Accept"; exit 0 ;;
  *"Received Access-Reject"*) echo "nas: Access-Reject"; exit 1 ;;
  *"Sent Access-Request"*)
    echo "nas: no reply from $SERVER after $TRIES attempts ($((TRIES * TIMEOUT))s): RADIUS server not responding"
    exit 2 ;;
  *)
    printf '%s\n' "$out" >&2
    echo "nas: request not sent" >&2
    exit 2 ;;
esac
