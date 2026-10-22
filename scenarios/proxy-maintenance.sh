# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# An admin puts the reverse proxy into maintenance mode for a Keycloak
# upgrade (a `return 503` with a maintenance page in front of Keycloak) and
# forgets to take it out afterwards. Keycloak is up and healthy, but every
# sign-in through the proxy gets the maintenance page, a 503 that nginx
# makes itself without contacting Keycloak. The proxy's health check and
# Keycloak's own port (8180) keep working, so monitoring stays green. The
# OIDC RP behind the proxy breaks too, earlier: its own back-channel calls
# (discovery, token) go through the proxy and get the 503.
SCENARIO_SUMMARY="the proxy is left in maintenance mode: 503 for Keycloak, which is healthy"
SCENARIO_RUNBOOK="runbooks/17-service-unavailable.md"
SCENARIO_APP=saml-proxy
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="Sign-in is down for planned maintenance"
SCENARIO_SEEN_AT="on the proxy's maintenance page (HTTP 503) where Keycloak's login form should be, straight after \"Log in\"."
# upstream=- : nginx answered by itself, unlike a 502 or 504.
SCENARIO_LOG='proxy " 503 [0-9]+ host=[^ ]*:8183 upstream=- upstream_status=-'
SCENARIO_ALSO="the 503 carries Retry-After, and the proxy's health check still answers 200"

_pm_file=kc-maintenance.conf

# The include file holds a whole HTML page; status shows a summary of it.
scenario_detect() {
  local out
  out="$(proxy_conf_detect "$_pm_file" "")"
  case "${out%%$'\t'*}" in
    broken) printf 'broken\t%s: return 503 with a maintenance page (maintenance mode is on)\n' "$_pm_file" ;;
    *)      printf '%s\n' "$out" ;;
  esac
}

scenario_break() {
  proxy_conf_set "$_pm_file" <<'CONF'
# Maintenance mode for Keycloak through the proxy: ON, for the Keycloak
# upgrade. Broken by scenarios/proxy-maintenance.sh: left on afterwards.
default_type text/html;
add_header Retry-After 3600 always;
return 503 '<!doctype html><html><head><title>Planned maintenance</title></head><body><h1>Sign-in is down for planned maintenance</h1><p>We are upgrading the sign-in service. Please try again later.</p></body></html>\n';
CONF
}
scenario_fix() { proxy_conf_restore "$_pm_file"; }

# shellcheck disable=SC2329  # invoked by scripts/test.sh while broken
scenario_also_check() {
  local base="https://$LAB_HOST:$PROXY_KC_PORT" args out
  args=(-sS --cacert "$CERTS_DIR/ca.crt" --resolve "$LAB_HOST:$PROXY_KC_PORT:127.0.0.1")
  out="$(curl "${args[@]}" -o /dev/null -D - "$base/realms/$REALM/.well-known/openid-configuration" | tr -d '\r')"
  grep -iE '^(HTTP/|retry-after:)' <<<"$out"
  head -n1 <<<"$out" | grep -q ' 503' || { echo "expected HTTP 503"; return 1; }
  grep -qi '^retry-after: 3600$' <<<"$out" || { echo "expected Retry-After: 3600"; return 1; }
  out="$(curl "${args[@]}" -o /dev/null -w '%{http_code}' "$base/nginx-healthz")"
  echo "/nginx-healthz: $out"
  [[ "$out" == 200 ]]
}
