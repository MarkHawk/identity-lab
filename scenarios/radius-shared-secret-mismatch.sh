# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The shared secret configured on the NAS no longer matches the one in the
# RADIUS server's client entry for it (as when someone retypes it on the NAS
# during a replacement or a config restore). The server can't verify the
# NAS's packets, so it drops them without replying: the NAS sees a timeout,
# for every user. Web logins through Keycloak use the same directory and are
# unaffected. The server side is never touched.
SCENARIO_SUMMARY="the NAS's RADIUS shared secret no longer matches the server's"
SCENARIO_RUNBOOK="runbooks/05-radius-shared-secret-mismatch.md"
SCENARIO_APP=radius
SCENARIO_USER=dave
SCENARIO_UNAFFECTED="oidc dave"
SCENARIO_EXPECT="RADIUS server not responding"
SCENARIO_SEEN_AT="in nas-auth's output, after about 6 seconds (3 attempts)"
SCENARIO_LOG='radius with invalid Message-Authenticator! .*Shared secret is incorrect'

_rsm_wrong="not-the-radius-secret"   # deliberately wrong, not a secret
_rsm_file=/var/lib/nas/secret
_rsm_nas="nas (172.30.181.10)"

# _rsm_set <secret> -- store the NAS's copy of the secret, the way an admin
# types it into a NAS. The value goes in on stdin, never a command line.
_rsm_set() {
  printf '%s' "$1" | compose exec -T nas sh -c \
    "umask 077 && cat >$_rsm_file.tmp && mv $_rsm_file.tmp $_rsm_file"
}

# The server reads RADIUS_SECRET from .env at start, so compare the NAS's
# copy with that. cmp reads the expected value on stdin and prints nothing.
scenario_detect() {
  local rc=0
  [[ -n "$(compose ps -q --status running nas 2>/dev/null)" ]] \
    || { printf 'unknown\tthe nas container is not running\n'; return; }
  printf '%s' "$RADIUS_SECRET" | compose exec -T nas cmp -s - "$_rsm_file" || rc=$?
  case "$rc" in
    0) printf 'healthy\t%s has the same shared secret as the server\n' "$_rsm_nas" ;;
    1) printf 'broken\t%s has a different shared secret from the server'"'"'s client entry\n' "$_rsm_nas" ;;
    *) printf 'unknown\tcould not read the shared secret on %s (cmp exit %s)\n' "$_rsm_nas" "$rc" ;;
  esac
}

scenario_break() { _rsm_set "$_rsm_wrong"; }
scenario_fix()   { _rsm_set "$RADIUS_SECRET"; }
