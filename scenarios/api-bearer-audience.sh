# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# Someone copies the oidc-rp client's settings from a staging export, and
# its audience mapper now names the staging API: Keycloak puts
# aud=idlab-api-staging in the access tokens instead of idlab-api. The login
# still works, because the ID token is unchanged; the API rejects every call
# with 401 and WWW-Authenticate error="invalid_token".
SCENARIO_SUMMARY="oidc-rp's access tokens name another API in their audience"
SCENARIO_RUNBOOK="runbooks/16-api-bearer-401.md"
SCENARIO_APP=oidc-api
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="audience (idlab-api-staging account) does not include idlab-api"
SCENARIO_SEEN_AT="on the OIDC RP's debug page after \"Call the API\" (API call failed: 401 UNAUTHORIZED, with the WWW-Authenticate header)"
SCENARIO_LOG='api event=api_token_rejected error=invalid_token .*audience'

_aba_mapper="audience idlab-api"
_aba_expected=idlab-api
_aba_wrong=idlab-api-staging

_aba_client_id() { kc_api GET "/$REALM/clients?clientId=oidc-rp" | jq -r '.[0].id // empty'; }
_aba_mapper_json() { kc_api GET "/$REALM/clients/$1/protocol-mappers/models" | jq -c --arg n "$_aba_mapper" '.[] | select(.name == $n)'; }

_aba_set() {
  local id mapper
  id="$(_aba_client_id)"; [[ -n "$id" ]] || die "client oidc-rp not found in realm $REALM"
  mapper="$(_aba_mapper_json "$id")"; [[ -n "$mapper" ]] || die "mapper '$_aba_mapper' not found on oidc-rp"
  kc_api PUT "/$REALM/clients/$id/protocol-mappers/models/$(jq -r .id <<<"$mapper")" \
    "$(jq -c --arg a "$1" '.config["included.custom.audience"] = $a' <<<"$mapper")"
}

scenario_detect() {
  local id mapper aud
  id="$(_aba_client_id 2>/dev/null)" || { printf 'unknown\tKeycloak admin API unreachable\n'; return; }
  [[ -n "$id" ]] || { printf 'unknown\tclient oidc-rp not found\n'; return; }
  mapper="$(_aba_mapper_json "$id" 2>/dev/null)"
  [[ -n "$mapper" ]] || { printf 'unknown\tmapper "%s" not found on oidc-rp\n' "$_aba_mapper"; return; }
  aud="$(jq -r '.config["included.custom.audience"] // ""' <<<"$mapper")"
  if [[ "$aud" == "$_aba_expected" ]]; then
    printf 'healthy\toidc-rp access tokens get aud %s\n' "$aud"
  else
    printf 'broken\toidc-rp access tokens get aud %s, the API expects %s\n' "${aud:-(none)}" "$_aba_expected"
  fi
}

scenario_break() { _aba_set "$_aba_wrong"; }
scenario_fix()   { _aba_set "$_aba_expected"; }
