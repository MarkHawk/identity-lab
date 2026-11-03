# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# An admin "hardens" the realm's OTP policy to HmacSHA256 and 8 digits.
# Keycloak stores the algorithm, digits and period with each enrolment, so
# everyone already enrolled (grace) keeps working. New starters (ivan) are
# asked to enrol with the new values, but many authenticator apps ignore
# the algorithm and digits in the QR code and make SHA1, 6-digit codes
# anyway. Keycloak refuses the code on the setup page, so they can't finish
# enrolling, and can't sign in.
SCENARIO_SUMMARY="the realm's OTP policy now asks for HmacSHA256 and 8 digits; new starters' apps make SHA1, 6-digit codes"
SCENARIO_RUNBOOK="runbooks/21-otp-policy-changed.md"
SCENARIO_APP=oidc
SCENARIO_USER=ivan
SCENARIO_UNAFFECTED="oidc grace"
SCENARIO_EXPECT="Invalid authenticator code."
SCENARIO_SEEN_AT="on Keycloak's Mobile Authenticator Setup page, after he types the code his app shows"
# Keycloak raises no event for a refused setup code (only UPDATE_CREDENTIAL
# when one succeeds), so its log is silent: the evidence is that silence,
# the realm's policy, and the admin event for the change.
SCENARIO_LOG_ABSENT='keycloak type="[A-Z_]+_ERROR"'
SCENARIO_ALSO="the setup page asks new starters for SHA256 and 8 digits, and an admin event records the realm update"

_opc_healthy='{"otpPolicyAlgorithm":"HmacSHA1","otpPolicyDigits":6,"otpPolicyPeriod":30}'
_opc_wrong='{"otpPolicyAlgorithm":"HmacSHA256","otpPolicyDigits":8,"otpPolicyPeriod":30}'

_opc_live() { kc_api GET "/$REALM" | jq -c '{otpPolicyAlgorithm, otpPolicyDigits, otpPolicyPeriod}'; }
_opc_show() { jq -r '"\(.otpPolicyAlgorithm), \(.otpPolicyDigits) digits, \(.otpPolicyPeriod) s"' <<<"$1"; }

scenario_detect() {
  local live
  live="$(_opc_live 2>/dev/null)" || { printf 'unknown\tKeycloak admin API unreachable\n'; return; }
  if [[ "$live" == "$_opc_healthy" ]]; then
    printf 'healthy\trealm OTP policy: %s, what authenticator apps make\n' "$(_opc_show "$live")"
  else
    printf 'broken\trealm OTP policy: %s; new enrolments must match it, existing ones keep their own\n' "$(_opc_show "$live")"
  fi
}

# As the admin console's OTP policy tab saves it: the whole realm, with the
# policy changed. (Keycloak ignores a partial update that leaves out
# otpPolicyType, so the policy can't be sent on its own.)
_opc_set() {
  local rep
  rep="$(kc_api GET "/$REALM")" || die "Keycloak admin API unreachable"
  kc_api PUT "/$REALM" "$(jq -c --argjson p "$1" '. + $p' <<<"$rep")" >/dev/null
}
scenario_break() { _opc_set "$_opc_wrong"; }
scenario_fix()   { _opc_set "$_opc_healthy"; }

# shellcheck disable=SC2329  # invoked by test.sh while broken (SCENARIO_ALSO)
scenario_also_check() {
  local out rc=0 events
  out="$(login_as ivan oidc --expect-error "Invalid authenticator code." 2>&1)" || rc=$?
  grep -F '[enrol]' <<<"$out" || true
  # Who changed it, and when: the realm's admin events (no details are kept).
  events="$(kc_api GET "/$REALM/admin-events?operationTypes=UPDATE&resourceTypes=REALM&max=5")" || return 1
  jq -r '.[] | "admin event: \(.operationType) \(.resourceType) at \(.time / 1000 | todate) from \(.authDetails.ipAddress)"' <<<"$events"
  (( rc == 0 )) && grep -qF 'Algorithm: SHA256, Digits: 8' <<<"$out" \
    && (( $(jq --argjson since "$(( ($(date +%s) - 300) * 1000 ))" '[.[] | select(.time >= $since)] | length' <<<"$events") > 0 ))
}
