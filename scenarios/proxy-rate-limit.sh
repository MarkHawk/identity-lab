# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# Someone tightens the reverse proxy's rate limit on Keycloak's /realms/
# endpoints, from 10 requests a second (burst 20) to 6 a minute with no
# burst, perhaps meaning to slow down password guessing. A login needs
# several /realms/ requests within seconds, so the login page loads and
# then submitting the password gets 429 Too Many Requests. Behind a proxy
# or NAT every user shares one client address, so all of them are
# limited together. The direct path (:8180) has no limit.
SCENARIO_SUMMARY="the proxy's rate limit on Keycloak is tighter than a login needs"
SCENARIO_RUNBOOK="runbooks/08-proxy-rate-limit.md"
SCENARIO_APP=oidc-proxy
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="429 Too Many Requests"
SCENARIO_SEEN_AT="on an nginx error page when you submit the password"
SCENARIO_LOG='proxy limiting requests, excess: [0-9.]+ by zone "kc_login"'

_prl_zone=rate-limit-zone.conf
_prl_limit=rate-limit.conf

scenario_detect() {
  local zone limit
  zone="$(proxy_conf_detect "$_prl_zone" "tighter than a login needs")"
  limit="$(proxy_conf_detect "$_prl_limit" "no burst allowance")"
  case "${zone%%$'\t'*} ${limit%%$'\t'*}" in
    "healthy healthy") printf 'healthy\t%s / %s\n' "${zone#*$'\t'}" "${limit#*$'\t'}" ;;
    *unknown*)         printf 'unknown\t%s / %s\n' "${zone#*$'\t'}" "${limit#*$'\t'}" ;;
    *)                 printf 'broken\t%s / %s\n'  "${zone#*$'\t'}" "${limit#*$'\t'}" ;;
  esac
}

scenario_break() {
  proxy_conf_set "$_prl_zone" <<'CONF'
# Rate limit for Keycloak's /realms/ endpoints. Broken by scenarios/proxy-rate-limit.sh.
limit_req_zone $binary_remote_addr zone=kc_login:1m rate=6r/m;
CONF
  proxy_conf_set "$_prl_limit" <<'CONF'
# Applies the kc_login zone to /realms/. Broken by scenarios/proxy-rate-limit.sh.
limit_req zone=kc_login;
CONF
}
scenario_fix() { proxy_conf_restore "$_prl_limit"; proxy_conf_restore "$_prl_zone"; }
