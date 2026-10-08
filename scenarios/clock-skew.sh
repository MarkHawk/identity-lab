# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The SAML SP's clock runs 10 minutes fast -- outside python3-saml's
# 300-second drift allowance -- so every assertion already looks expired.
# Only the saml-sp container's clock is shifted (libfaketime); the host
# clock is never touched.
SCENARIO_SUMMARY="SAML SP clock 10 minutes ahead of the IdP"
SCENARIO_RUNBOOK="runbooks/02-clock-skew.md"
SCENARIO_APP=saml
SCENARIO_EXPECT="Could not validate timestamp: expired. Check system clock."
SCENARIO_SEEN_AT="on the SAML SP error page after you sign in"
SCENARIO_LOG='saml-sp saml_login_failed.*Could not validate timestamp'

_cs_file="$STATE_DIR/saml-sp/faketime.rc"
_cs_offset="+600"
_cs_tolerance=60   # seconds of difference still reported as healthy

scenario_detect() {
  local sp host diff
  sp="$(compose exec -T saml-sp date -u +%s 2>/dev/null)" \
    || { printf 'unknown\tsaml-sp container is not running\n'; return; }
  host="$(date -u +%s)"
  diff=$(( sp - host ))
  if (( diff > _cs_tolerance || diff < -_cs_tolerance )); then
    printf 'broken\tsaml-sp clock is %+ds vs host (faketime offset %s)\n' "$diff" "$(cat "$_cs_file")"
  else
    printf 'healthy\tsaml-sp clock is %+ds vs host\n' "$diff"
  fi
}

# libfaketime re-reads this file on every clock call (FAKETIME_NO_CACHE=1).
scenario_break() { mkdir -p "$(dirname "$_cs_file")"; printf '%s\n' "$_cs_offset" >"$_cs_file"; sleep 1; }
scenario_fix()   { mkdir -p "$(dirname "$_cs_file")"; printf '+0\n' >"$_cs_file"; sleep 1; }
