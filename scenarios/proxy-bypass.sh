# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# Someone "tidies up" the OIDC RP's proxy settings and adds the internal
# names to NO_PROXY, on the rule that internal traffic shouldn't go through
# the proxy (a common copied default). Keycloak's name, keycloak, is one of
# them, so the RP now calls it directly. But the RP's network has no route
# to Keycloak except through the proxy, so the name doesn't even resolve,
# and every login through that RP fails. Squid sees nothing at all.
SCENARIO_SUMMARY="NO_PROXY sends the OIDC RP's calls to the IdP around the egress proxy"
SCENARIO_RUNBOOK="runbooks/14-proxy-bypass.md"
SCENARIO_APP=oidc-egress
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="Failed to resolve 'keycloak'"
SCENARIO_SEEN_AT="on the app's \"OIDC login failed\" page, straight after \"Log in\" (the change restarted the app)"
SCENARIO_LOG='oidc-rp-egress event=oidc_login_failed reason=backchannel_failed .*NameResolutionError'

scenario_detect() { egress_env_detect "the RP's only route to keycloak is the proxy"; }

scenario_break() {
  egress_env_set <<'ENV'
# Proxy settings of oidc-rp-egress. Broken by scenarios/proxy-bypass.sh.
HTTPS_PROXY=http://squid:3128
NO_PROXY=localhost,127.0.0.1,keycloak,.idlab.example
ENV
}
scenario_fix() { egress_env_restore; }
