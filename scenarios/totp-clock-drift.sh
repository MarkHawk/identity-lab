# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The clock on grace's phone (the authenticator app) runs 3 minutes fast, as
# when someone turns off automatic time and sets it by hand, or a phone has
# been offline for months. Her codes are for a time step 6 steps (of 30 s)
# ahead; Keycloak accepts the current step and one either side (look-around
# window 1), so every code she types fails. Her password is still accepted.
# Only the authenticator container's clock moves (libfaketime); the IdP's
# and the host's are untouched.
SCENARIO_SUMMARY="the clock on grace's authenticator app runs 3 minutes fast"
SCENARIO_RUNBOOK="runbooks/20-totp-clock-drift.md"
SCENARIO_APP=oidc
SCENARIO_USER=grace
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="Invalid authenticator code."
SCENARIO_SEEN_AT="on Keycloak's one-time code form, after her password is accepted"
SCENARIO_LOG='keycloak type="LOGIN_ERROR".*error="invalid_user_credentials"'
SCENARIO_ALSO="Keycloak's clock agrees with the host's; only the phone's is out"

_tcd_file="$STATE_DIR/authenticator/faketime.rc"
_tcd_offset="+180"
# Under 30 s every code still works; from 30 s some fail, and from 60 s all.
_tcd_tolerance=30

_tcd_clock_diff() { # <service> -- its clock minus the host's, in seconds
  local c
  c="$(compose exec -T "$1" date -u +%s 2>/dev/null)" || return 1
  echo $(( c - $(date -u +%s) ))
}

scenario_detect() {
  local diff
  diff="$(_tcd_clock_diff authenticator)" \
    || { printf 'unknown\tthe authenticator container is not running\n'; return; }
  if (( diff >= _tcd_tolerance || diff <= -_tcd_tolerance )); then
    printf 'broken\tthe authenticator app'"'"'s clock is %+ds vs host, %+d steps of 30 s (faketime offset %s); Keycloak looks 1 step either side\n' \
      "$diff" "$(( diff / 30 ))" "$(cat "$_tcd_file")"
  else
    printf 'healthy\tthe authenticator app'"'"'s clock is %+ds vs host\n' "$diff"
  fi
}

# libfaketime re-reads this file on every clock call (FAKETIME_NO_CACHE=1).
scenario_break() { mkdir -p "${_tcd_file%/*}"; printf '%s\n' "$_tcd_offset" >"$_tcd_file"; sleep 1; }
scenario_fix()   { mkdir -p "${_tcd_file%/*}"; printf '+0\n' >"$_tcd_file"; sleep 1; }

# shellcheck disable=SC2329  # invoked by test.sh while broken (SCENARIO_ALSO)
scenario_also_check() {
  local kc phone
  kc="$(_tcd_clock_diff keycloak)" || { echo "could not read Keycloak's clock"; return 1; }
  phone="$(_tcd_clock_diff authenticator)" || { echo "could not read the authenticator's clock"; return 1; }
  echo "Keycloak clock vs host: ${kc}s; authenticator app clock vs host: ${phone}s"
  (( kc > -5 && kc < 5 && (phone >= _tcd_tolerance || phone <= -_tcd_tolerance) ))
}
