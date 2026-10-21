# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The egress proxy's URL filtering policy gets a rule that refuses the IdP
# (as when a blocklist update or a new "deny uncategorised destinations"
# rule catches an internal or newly moved IdP hostname). Squid answers the
# OIDC RP's CONNECT to Keycloak with 403 Forbidden, so every login through
# that RP fails. Keycloak never sees the request; the direct RP (:8182)
# doesn't use the proxy and keeps working.
SCENARIO_SUMMARY="the egress proxy's policy refuses connections to the IdP"
SCENARIO_RUNBOOK="runbooks/12-proxy-policy-block.md"
SCENARIO_APP=oidc-egress
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="Tunnel connection failed: 403 Forbidden"
SCENARIO_SEEN_AT="on the app's \"OIDC login failed\" page, after the password (or straight after \"Log in\" if the app restarted since its last login)"
SCENARIO_LOG='squid TCP_DENIED/403 [0-9]+ CONNECT keycloak:8180'

_ppb_file=policy.conf

scenario_detect() { squid_conf_detect "$_ppb_file" "keycloak is the IdP the RP needs"; }

scenario_break() {
  squid_conf_set "$_ppb_file" <<'CONF'
# Destinations the proxy refuses (URL filtering policy). Broken by scenarios/proxy-policy-block.sh.
acl blocked_sites dstdomain keycloak .unapproved.example
http_access deny CONNECT blocked_sites
CONF
}
scenario_fix() { squid_conf_restore "$_ppb_file"; }
