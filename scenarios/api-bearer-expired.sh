# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# A Keycloak admin shortens oidc-rp's access token lifespan to 10 seconds
# (hardening, or a typo for 10 minutes). The OIDC RP keeps the access token
# it got at login and never refreshes it, so any API call made more than
# 10 seconds after login gets 401 with WWW-Authenticate error="invalid_token"
# and "The access token expired". A call straight after login still works.
SCENARIO_SUMMARY="oidc-rp's access tokens expire after 10 seconds; the app never refreshes them"
SCENARIO_RUNBOOK="runbooks/16-api-bearer-401.md"
SCENARIO_APP=oidc-api-late
SCENARIO_UNAFFECTED="oidc-api alice"
SCENARIO_EXPECT="The access token expired at"
SCENARIO_SEEN_AT="on the OIDC RP's debug page after \"Call the API\", more than 10 seconds after login (API call failed: 401 UNAUTHORIZED)"
SCENARIO_LOG='api event=api_token_rejected error=invalid_token .*expired at'

_abe_attr=access.token.lifespan
_abe_wrong=10

_abe_client() { kc_api GET "/$REALM/clients?clientId=oidc-rp" | jq -c '.[0] // empty'; }

# An empty value means "use the realm's lifespan", as the admin console sets it.
_abe_set() {
  local client
  client="$(_abe_client)"; [[ -n "$client" ]] || die "client oidc-rp not found in realm $REALM"
  kc_api PUT "/$REALM/clients/$(jq -r .id <<<"$client")" \
    "$(jq -c --arg k "$_abe_attr" --arg v "$1" '.attributes[$k] = $v' <<<"$client")"
}

scenario_detect() {
  local client v
  client="$(_abe_client 2>/dev/null)" || { printf 'unknown\tKeycloak admin API unreachable\n'; return; }
  [[ -n "$client" ]] || { printf 'unknown\tclient oidc-rp not found\n'; return; }
  v="$(jq -r --arg k "$_abe_attr" '.attributes[$k] // ""' <<<"$client")"
  if [[ -z "$v" ]]; then
    printf 'healthy\toidc-rp access tokens use the realm lifespan (%s not set)\n' "$_abe_attr"
  else
    printf 'broken\toidc-rp %s=%ss, shorter than the RP keeps using its token\n' "$_abe_attr" "$v"
  fi
}

scenario_break() { _abe_set "$_abe_wrong"; }
scenario_fix()   { _abe_set ""; }
