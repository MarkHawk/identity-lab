# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# Someone edits the reverse proxy's upstream for the OIDC RP and writes
# http:// where the app only speaks HTTPS (as when a config is copied from a
# site whose backend is plain HTTP, or "TLS to the backend" is turned off on
# the proxy but not on the app). nginx sends plain HTTP to a TLS port, the
# app hangs up, and every request through the proxy gets a 502. The app
# itself is healthy, and the direct path (:8182) keeps working.
SCENARIO_SUMMARY="the proxy sends plain HTTP to the OIDC RP's HTTPS port"
SCENARIO_RUNBOOK="runbooks/06-proxy-bad-gateway.md"
SCENARIO_APP=oidc-proxy
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="502 Bad Gateway"
SCENARIO_SEEN_AT="on an nginx error page, before the app's own page loads"
SCENARIO_LOG='proxy upstream prematurely closed connection while reading response header from upstream'

_pbg_file=oidc-rp-upstream.conf

scenario_detect() { proxy_conf_detect "$_pbg_file" "the upstream speaks HTTPS only"; }

scenario_break() {
  proxy_conf_set "$_pbg_file" <<'CONF'
# Where the proxy sends https://LAB_HOST:8185. Broken by scenarios/proxy-bad-gateway.sh.
proxy_pass http://oidc_rp_proxied;
CONF
}
scenario_fix() { proxy_conf_restore "$_pbg_file"; }
