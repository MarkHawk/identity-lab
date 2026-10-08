# shellcheck shell=bash
# Someone edits the oidc-rp client in Keycloak and the registered redirect
# URI no longer matches the one the app sends (/callback vs /auth/callback).
SCENARIO_SUMMARY="oidc-rp client's registered redirect URI no longer matches the app"
SCENARIO_RUNBOOK="runbooks/03-redirect-uri-mismatch.md"
SCENARIO_APP=oidc
SCENARIO_EXPECT="Invalid parameter: redirect_uri"
SCENARIO_LOG='keycloak error="invalid_redirect_uri"'

_rum_expected="https://$LAB_HOST:$OIDC_RP_PORT/auth/callback"
_rum_wrong="https://$LAB_HOST:$OIDC_RP_PORT/callback"

_rum_client() { kc_api GET "/$REALM/clients?clientId=oidc-rp" | jq -c '.[0] // empty'; }

_rum_set() {
  local client
  client="$(_rum_client)"
  [[ -n "$client" ]] || die "client oidc-rp not found in realm $REALM"
  kc_api PUT "/$REALM/clients/$(jq -r .id <<<"$client")" \
    "$(jq -c --arg u "$1" '.redirectUris = [$u]' <<<"$client")"
}

scenario_detect() {
  local client uris
  client="$(_rum_client 2>/dev/null)" || { printf 'unknown\tKeycloak admin API unreachable\n'; return; }
  [[ -n "$client" ]] || { printf 'unknown\tclient oidc-rp not found\n'; return; }
  uris="$(jq -r '.redirectUris | join(" ")' <<<"$client")"
  if jq -e --arg u "$_rum_expected" '.redirectUris | index($u)' <<<"$client" >/dev/null; then
    printf 'healthy\tredirectUris=%s\n' "$uris"
  else
    printf 'broken\tredirectUris=%s (app sends %s)\n' "$uris" "$_rum_expected"
  fi
}

scenario_break() { _rum_set "$_rum_wrong"; }
scenario_fix()   { _rum_set "$_rum_expected"; }
