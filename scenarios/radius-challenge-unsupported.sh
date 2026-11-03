# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# MFA is on at the RADIUS server for heidi (the directory's mfa-required
# group): after her password it answers Access-Challenge and waits for a
# one-time code. But her NAS doesn't do challenge-response (a replacement
# model, older firmware, or a profile set to plain PAP), so, as RFC 2865
# requires of such a NAS, it treats the challenge as an Access-Reject. She
# is never asked for a code; she just sees the login fail. dave, who needs
# no second factor, logs in through the same NAS. The server isn't touched.
SCENARIO_SUMMARY="the NAS doesn't do challenge-response, so MFA users get Access-Reject"
SCENARIO_RUNBOOK="runbooks/23-radius-challenge-unsupported.md"
SCENARIO_APP=radius
SCENARIO_USER=heidi
SCENARIO_UNAFFECTED="radius dave"
SCENARIO_EXPECT="nas: Access-Reject"
SCENARIO_SEEN_AT="in nas-auth's output, straight after the password: it never asks for the code"
SCENARIO_LOG='radius Auth: Challenge sent: \[heidi\]'
SCENARIO_ALSO="the NAS discarded the challenge, and the server got no second request: no Login OK or Login incorrect for heidi"

_rcu_file=/var/lib/nas/challenge
_rcu_nas="nas (172.30.181.10)"

# _rcu_set <yes|no> -- the NAS's challenge-response setting, in its volume.
_rcu_set() {
  compose exec -T nas sh -c "printf '%s\n' '$1' >$_rcu_file.tmp && mv $_rcu_file.tmp $_rcu_file"
}

scenario_detect() {
  local v
  [[ -n "$(compose ps -q --status running nas 2>/dev/null)" ]] \
    || { printf 'unknown\tthe nas container is not running\n'; return; }
  v="$(compose exec -T nas cat "$_rcu_file" 2>/dev/null)" \
    || { printf 'unknown\tno challenge-response setting on %s (%s)\n' "$_rcu_nas" "$_rcu_file"; return; }
  case "$v" in
    yes) printf 'healthy\t%s answers Access-Challenge (challenge-response on)\n' "$_rcu_nas" ;;
    no)  printf 'broken\t%s treats Access-Challenge as Access-Reject (challenge-response off)\n' "$_rcu_nas" ;;
    *)   printf 'unknown\t%s has challenge-response set to "%s"\n' "$_rcu_nas" "$v" ;;
  esac
}

scenario_break() { _rcu_set no; }
scenario_fix()   { _rcu_set yes; }

# shellcheck disable=SC2329  # invoked by test.sh while broken (SCENARIO_ALSO)
scenario_also_check() {
  local since out nas_log radius_log
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  out="$(radius_login heidi demo "nas: Access-Reject" 2>&1)" || { echo "$out"; return 1; }
  sleep 1
  nas_log="$(compose logs --no-log-prefix --since "$since" nas)"
  radius_log="$(compose logs --no-log-prefix --since "$since" radius)"
  grep -F 'discarded: challenge-response not enabled' <<<"$nas_log" || { echo "the NAS logged no discarded challenge"; return 1; }
  grep -F 'Challenge sent: [heidi]' <<<"$radius_log" || { echo "the server sent no challenge"; return 1; }
  if grep -E 'Login (OK|incorrect).*\[heidi\]' <<<"$radius_log"; then
    echo "the server got a second request, or rejected the first"; return 1
  fi
  echo "no Login OK or Login incorrect for heidi: the NAS never sent a second request"
}
