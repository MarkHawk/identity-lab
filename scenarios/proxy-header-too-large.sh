# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# Someone shrinks the reverse proxy's buffer for Keycloak's response headers
# to 1k (to save memory, or copied from a config for a small API). Keycloak's
# login page sets its session cookies in about 2 KB of headers, so nginx
# can't hold the response header, gives up on it and returns 502: the login
# page never appears. Keycloak answered normally and logs nothing. The
# direct path (:8180) has no proxy in the way.
SCENARIO_SUMMARY="the proxy's header buffer for Keycloak is smaller than Keycloak's cookies"
SCENARIO_RUNBOOK="runbooks/10-proxy-header-too-large.md"
SCENARIO_APP=saml-proxy
SCENARIO_UNAFFECTED="saml alice"
SCENARIO_EXPECT="502 Bad Gateway"
SCENARIO_SEEN_AT="on an nginx error page where Keycloak's login page should be"
SCENARIO_LOG='proxy upstream sent too big header while reading response header from upstream'

_pht_file=kc-buffers.conf

scenario_detect() { proxy_conf_detect "$_pht_file" "Keycloak's login page sends about 2 KB of headers"; }

scenario_break() {
  proxy_conf_set "$_pht_file" <<'CONF'
# Room for Keycloak's response headers. Broken by scenarios/proxy-header-too-large.sh.
proxy_buffer_size       1k;
proxy_buffers           8 16k;
proxy_busy_buffers_size 32k;
CONF
}
scenario_fix() { proxy_conf_restore "$_pht_file"; }
