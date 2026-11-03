# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# grace types five wrong one-time codes (a phone whose clock is wrong, the
# wrong account in her app, or someone with her password guessing), a few
# seconds apart. Brute-force protection counts each as a failed login and,
# at the realm's failureFactor of 5, locks her account for 5 minutes. While
# it lasts, her right password and right code fail too, and Keycloak tells
# her only "Invalid username or password." -- on purpose, so an attacker
# can't tell a locked account from a wrong guess.
#
# The attempts are 3 seconds apart, longer than quickLoginCheckMilliSeconds
# (1 s), so the lockout comes from the failure count (failureFactor), not
# from the quick-login rule, which locks for a minute after two failures
# within a second. scenario_detect says which rule it was.
SCENARIO_SUMMARY="grace's account is locked after five wrong one-time codes"
SCENARIO_RUNBOOK="runbooks/22-mfa-lockout.md"
SCENARIO_APP=oidc
SCENARIO_USER=grace
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="Invalid username or password."
SCENARIO_SEEN_AT="on Keycloak's login form, after her (correct) password"
SCENARIO_LOG='keycloak type="LOGIN_ERROR".*error="user_temporarily_disabled"'
SCENARIO_ALSO="the lockout came from 5 failed codes (failureFactor), not the quick-login rule"

_ml_user=grace
_ml_attempts=5
_ml_gap=3   # seconds between attempts; more than quickLoginCheckMilliSeconds

# _ml_rule <status-json> <failureFactor> -- which rule locked the account
_ml_rule() {
  local n
  n="$(jq -r .numFailures <<<"$1")"
  if (( n >= $2 )); then echo "max failures: $n failed logins, failureFactor $2"
  else echo "quick login: $n failed login(s), two of them less than quickLoginCheckMilliSeconds apart"; fi
}

scenario_detect() {
  local st rep ff
  st="$(bf_status "$_ml_user" 2>/dev/null)" || { printf 'unknown\tKeycloak admin API unreachable, or no user %s\n' "$_ml_user"; return; }
  rep="$(kc_api GET "/$REALM" 2>/dev/null)" || { printf 'unknown\tKeycloak admin API unreachable\n'; return; }
  [[ "$(jq -r .bruteForceProtected <<<"$rep")" == true ]] \
    || { printf 'unknown\tbrute-force protection is off for the realm (it is on in the realm import)\n'; return; }
  ff="$(jq -r .failureFactor <<<"$rep")"
  if [[ "$(jq -r .disabled <<<"$st")" == true ]]; then
    printf 'broken\t%s is temporarily locked out (%s)\n' "$_ml_user" "$(_ml_rule "$st" "$ff")"
  else
    printf 'healthy\t%s is not locked out (%s failed login(s) recorded, lockout at %s)\n' \
      "$_ml_user" "$(jq -r .numFailures <<<"$st")" "$ff"
  fi
}

scenario_break() {
  local i code out
  for (( i = 1; i <= _ml_attempts; i++ )); do
    (( i == 1 )) || sleep "$_ml_gap"
    # A wrong code, as her app would show with the wrong clock or account.
    code="$(compose exec -T authenticator authenticator code "$_ml_user" --wrong)"
    out="$(kc_form_login "$_ml_user" "$code")"
    [[ "$out" == code-refused ]] || die "attempt $i of $_ml_attempts: expected the code to be refused, got: $out"
  done
}
scenario_fix() { bf_clear "$_ml_user"; }

# shellcheck disable=SC2329  # invoked by test.sh while broken (SCENARIO_ALSO)
scenario_also_check() {
  local st ff
  st="$(bf_status "$_ml_user")" || return 1
  ff="$(kc_api GET "/$REALM" | jq -r .failureFactor)"
  echo "$_ml_user: $(jq -c '{numFailures, numSecondaryAuthFailures, disabled}' <<<"$st"); $(_ml_rule "$st" "$ff")"
  [[ "$(jq -r .disabled <<<"$st")" == true ]] && (( $(jq -r .numFailures <<<"$st") >= ff ))
}
