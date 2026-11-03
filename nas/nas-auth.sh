#!/usr/bin/env bash
# Send one login to the lab's RADIUS server, as a NAS does when a user logs
# in, and print the outcome.
#
#   nas-auth <user>                                     prompts for the password (hidden),
#                                                       and for a one-time code if challenged
#   printf '%s\n' "$pw" | nas-auth <user>               reads the password from stdin
#   printf '%s\n%s\n' "$pw" "$code" | nas-auth <user>   and, if challenged, the code
#
# radclient (3.2.10) always adds Message-Authenticator, as a current NAS does,
# and checks the server's reply against the shared secret: a reply whose
# Response Authenticator or Message-Authenticator doesn't verify is dropped,
# as if it never came.
#
# Access-Challenge (MFA): the server wants a one-time code after the
# password. The challenge must carry Message-Authenticator (BlastRADIUS,
# CVE-2024-3596), or it is discarded before its State is used. Then:
#   - with challenge-response on (/var/lib/nas/challenge is "yes"), the NAS
#     shows the server's Reply-Message, reads the code, and sends a second
#     Access-Request with it and the server's State;
#   - with it off ("no"), the NAS does what RFC 2865 (4.4) requires of one
#     that can't prompt: it treats the challenge as an Access-Reject.
# Discarded challenges are also logged to the container's log, as a NAS
# logs to syslog (docker compose logs nas).
#
# The shared secret comes from the NAS's own file, and the password and
# code from stdin: none of them is ever on a command line or printed.
# Exit status: 0 Access-Accept, 1 Access-Reject, 2 no reply or other error.
set -euo pipefail

SECRET_FILE=/var/lib/nas/secret
CHALLENGE_FILE=/var/lib/nas/challenge
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

# nas_log <message> -- to the container's log, as a NAS logs to syslog.
nas_log() { printf '%s nas: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >/proc/1/fd/1 2>/dev/null || true; }

# send <request attributes on stdin> -- one Access-Request; prints only the
# reply radclient received (-x also prints the request, password included).
send() {
  radclient -x -r "$TRIES" -t "$TIMEOUT" -S "$SECRET_FILE" "$SERVER" auth 2>&1 \
    | awk '/^Received /{r = 1; print; next} /^[^\t]/{r = 0; if (/^Sent /) sent = 1; next} r
           END {if (sent) print "Sent Access-Request"}' || true
}

# The reply's packet type and attributes.
reply_type() { sed -n 's/^Received \(Access-[A-Za-z]*\) .*/\1/p' <<<"$1" | head -n 1; }
reply_attr() { sed -n "s/^\t$1 = //p" <<<"$2" | head -n 1; }

# outcome <reply> -- print and exit for an Accept, a Reject or no reply.
outcome() {
  case "$(reply_type "$1")" in
    Access-Accept) echo "nas: Access-Accept"; exit 0 ;;
    Access-Reject) echo "nas: Access-Reject"; exit 1 ;;
    Access-Challenge) return 0 ;;
  esac
  if grep -q '^Sent Access-Request' <<<"$1"; then
    echo "nas: no reply from $SERVER after $TRIES attempts ($((TRIES * TIMEOUT))s): RADIUS server not responding"
    exit 2
  fi
  printf '%s\n' "$1" >&2
  echo "nas: request not sent" >&2
  exit 2
}

echo "nas: Access-Request for $user to $SERVER"
reply="$(printf 'User-Name = "%s"\nUser-Password = "%s"\nNAS-Identifier = "nas"\nMessage-Authenticator = 0x00\n' \
  "$(esc "$user")" "$(esc "$password")" | send)"
unset password
outcome "$reply"

# An Access-Challenge.
message="$(reply_attr Reply-Message "$reply" | sed 's/^"//; s/"$//')"
state="$(reply_attr State "$reply")"
if [[ -z "$(reply_attr Message-Authenticator "$reply")" ]]; then
  nas_log "Access-Challenge from $SERVER for $user discarded: no Message-Authenticator"
  echo "nas: Access-Challenge without Message-Authenticator discarded"
  echo "nas: no reply from $SERVER: RADIUS server not responding"
  exit 2
fi
if [[ "$(cat "$CHALLENGE_FILE" 2>/dev/null || echo yes)" != yes ]]; then
  nas_log "Access-Challenge from $SERVER for $user discarded: challenge-response not enabled (treated as Access-Reject)"
  echo "nas: Access-Reject"
  exit 1
fi
[[ "$state" =~ ^0x[0-9a-f]+$ ]] || { echo "nas: Access-Challenge without a usable State" >&2; exit 2; }

echo "nas: Access-Challenge (Message-Authenticator verified): ${message:-the server asks for more}"
if [[ -t 0 ]]; then
  read -r -s -p "${message:-Response}: " code; echo
else
  IFS= read -r code || [[ -n "$code" ]] || true
fi
echo "nas: Access-Request for $user to $SERVER, answering the challenge"
reply="$(printf 'User-Name = "%s"\nUser-Password = "%s"\nState = %s\nNAS-Identifier = "nas"\nMessage-Authenticator = 0x00\n' \
  "$(esc "$user")" "$(esc "${code:-}")" "$state" | send)"
unset code
outcome "$reply"
echo "nas: a second Access-Challenge; this NAS answers only one" >&2
exit 1
