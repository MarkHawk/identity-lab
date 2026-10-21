# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The egress proxy team turns on proxy login (as when a proxy moves from
# "trust the server network" to "every user and service account must log
# in"), and nobody gives the OIDC RP behind it an account. Squid answers
# the RP's CONNECT to Keycloak with 407 Proxy Authentication Required, so
# the RP can't reach the token endpoint and every login through it fails.
# Keycloak never sees the request; apps that don't use the proxy (the
# direct :8182) keep working.
SCENARIO_SUMMARY="the egress proxy requires a login the OIDC RP doesn't have"
SCENARIO_RUNBOOK="runbooks/11-proxy-auth-required.md"
SCENARIO_APP=oidc-egress
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="Tunnel connection failed: 407 Proxy Authentication Required"
SCENARIO_SEEN_AT="on the app's \"OIDC login failed\" page, after the password (or straight after \"Log in\" if the app restarted since its last login)"
SCENARIO_LOG='squid TCP_DENIED/407 [0-9]+ CONNECT keycloak:8180'

_par_file=auth.conf

scenario_detect() { squid_conf_detect "$_par_file" "the RP has no proxy credentials"; }

scenario_break() {
  squid_conf_set "$_par_file" <<'CONF'
# Proxy login. Broken by scenarios/proxy-auth-required.sh.
auth_param basic program /usr/local/squid/libexec/basic_ncsa_auth /tmp/squid-passwd
auth_param basic realm identity-lab egress proxy
acl egress_users proxy_auth REQUIRED
http_access deny !egress_users
CONF
}
scenario_fix() { squid_conf_restore "$_par_file"; }

# While broken: the account the proxy now asks for does get through, so the
# 407 is about missing credentials, not a wrong policy. The password goes to
# the RP container on stdin and only the status comes back.
SCENARIO_ALSO="egress-svc with its password gets through Squid"
scenario_also_check() {
  local out
  # shellcheck disable=SC2016  # Python, not shell
  out="$(printf '%s' "$EGRESS_PROXY_PASSWORD" | compose exec -T oidc-rp-egress python -c '
import sys, urllib.parse, requests
proxy = "http://egress-svc:%s@squid:3128" % urllib.parse.quote(sys.stdin.read(), safe="")
try:
    r = requests.get("https://keycloak:8180/realms/idlab", proxies={"https": proxy}, timeout=5)
    print("status", r.status_code)
except requests.RequestException as e:
    print("failed:", type(e).__name__)' 2>&1)"
  echo "$out"
  [[ "$out" == "status 200" ]]
}
