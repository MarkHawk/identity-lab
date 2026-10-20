# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# Someone pastes a header block from a standard site on port 443 into the
# proxy's Keycloak route: X-Forwarded-Port 443 instead of the port the
# browser really used (8183). Keycloak builds its own URLs from that header,
# so it now believes it lives at https://LAB_HOST/ with no port: its issuer
# changes, a SAML AuthnRequest addressed to :8183 fails the destination
# check, and the OIDC login form posts to port 443, where nothing listens.
# The direct path (:8180) ignores X-Forwarded-* from anyone but the proxy.
SCENARIO_SUMMARY="the proxy tells Keycloak the browser used port 443, not 8183"
SCENARIO_RUNBOOK="runbooks/09-proxy-forwarded-headers.md"
SCENARIO_APP=saml-proxy
SCENARIO_UNAFFECTED="saml alice"
SCENARIO_EXPECT="Invalid Request"
SCENARIO_SEEN_AT="on a Keycloak error page (\"We are sorry...\"), before any login form"
SCENARIO_LOG='keycloak error="invalid_authn_request", reason="invalid_destination"'

_pfh_file=forwarded-headers.conf

# What Keycloak itself reports through the proxy decides it, with the
# header file as the detail.
scenario_detect() {
  local file iss want="https://$LAB_HOST:$PROXY_KC_PORT/realms/$REALM"
  file="$(proxy_conf_detect "$_pfh_file" "")"
  [[ "${file%%$'\t'*}" == unknown ]] && { printf '%s\n' "$file"; return; }
  iss="$(kc_curl --resolve "$LAB_HOST:$PROXY_KC_PORT:127.0.0.1" \
    "https://$LAB_HOST:$PROXY_KC_PORT/realms/$REALM/.well-known/openid-configuration" 2>/dev/null | jq -r .issuer 2>/dev/null)" \
    || { printf 'unknown\tKeycloak unreachable through the proxy\n'; return; }
  if [[ "$iss" == "$want" ]]; then
    printf 'healthy\tissuer through the proxy is %s\n' "$iss"
  else
    printf 'broken\tissuer through the proxy is %s, not %s (%s)\n' "$iss" "$want" \
      "$(proxy_conf_live "$_pfh_file" | grep -i 'x-forwarded-port' | sed 's/;$//')"
  fi
}

scenario_break() {
  proxy_conf_set "$_pfh_file" <<'CONF'
# Headers the proxy sends to Keycloak. Broken by scenarios/proxy-forwarded-headers.sh:
# a block copied from a site served on the standard port.
proxy_set_header Host              $http_host;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $host;
proxy_set_header X-Forwarded-Port  443;
CONF
}
scenario_fix() { proxy_conf_restore "$_pfh_file"; }
