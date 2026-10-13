# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The bind credential Keycloak's LDAP federation uses to search the directory
# no longer matches the service account's password (as after a password
# rotation on the directory side that nobody copied into the IdP). The
# directory answers every bind with result code 49, invalid credentials, so
# LDAP users cannot log in. Local Keycloak users are unaffected.
SCENARIO_SUMMARY="Keycloak's LDAP bind credential no longer matches the service account"
SCENARIO_RUNBOOK="runbooks/04-ldap-bind-failure.md"
SCENARIO_APP=oidc
SCENARIO_USER=dave
SCENARIO_UNAFFECTED="saml alice"
SCENARIO_EXPECT="Unexpected error when handling authentication request to identity provider."
SCENARIO_SEEN_AT="on a Keycloak error page after you sign in (an LDAP user who has never logged in before gets \"Invalid username or password.\" on the login form instead)"
SCENARIO_LOG='keycloak Caused by: .*LDAP: error code 49 - Invalid Credentials'

_lbf_wrong="not-the-bind-password"   # deliberately wrong, not a secret
_lbf_bind_dn="cn=keycloak-svc,ou=services,dc=idlab,dc=example"

_lbf_component() {
  kc_api GET "/$REALM/components?type=org.keycloak.storage.UserStorageProvider&name=idlab-ldap" \
    | jq -c '.[0] // empty'
}

# _lbf_set <credential> -- store a bind credential on the federation. The value
# reaches jq through the environment and curl on stdin, never a command line.
_lbf_set() {
  local -x _lbf_value="$1"
  local c
  c="$(_lbf_component)"
  [[ -n "$c" ]] || die "LDAP federation idlab-ldap not found in realm $REALM"
  kc_api PUT "/$REALM/components/$(jq -r .id <<<"$c")" \
    "$(jq -c '.config.bindCredential = [env._lbf_value]' <<<"$c")"
}

# Keycloak masks bindCredential on read, so ask Keycloak itself to bind with
# the stored credential: the admin console's "Test authentication" button.
scenario_detect() {
  local c body out rc=0 err
  c="$(_lbf_component 2>/dev/null)" || { printf 'unknown\tKeycloak admin API unreachable\n'; return; }
  [[ -n "$c" ]] || { printf 'unknown\tLDAP federation idlab-ldap not found (it is created at realm import: scripts/test.sh --fresh)\n'; return; }
  body="$(jq -c '{action: "testAuthentication", componentId: .id,
    connectionUrl: .config.connectionUrl[0], bindDn: .config.bindDn[0],
    bindCredential: .config.bindCredential[0], authType: .config.authType[0],
    useTruststoreSpi: .config.useTruststoreSpi[0]}' <<<"$c")"
  out="$(kc_api POST "/$REALM/testLDAPConnection" "$body" 2>/dev/null)" || rc=$?
  if (( rc == 0 )); then
    printf 'healthy\tKeycloak binds to %s as %s\n' "$(jq -r '.config.connectionUrl[0]' <<<"$c")" "$_lbf_bind_dn"
    return
  fi
  err="$(jq -r '.errorMessage // empty' <<<"$out" 2>/dev/null || true)"
  if [[ "$err" == AuthenticationFailure ]]; then
    printf 'broken\tKeycloak cannot bind as %s: LDAP result 49, invalid credentials\n' "$_lbf_bind_dn"
  else
    printf 'unknown\tKeycloak LDAP connection test failed: %s\n' "${err:-curl exit $rc}"
  fi
}

scenario_break() { _lbf_set "$_lbf_wrong"; }
scenario_fix()   { _lbf_set "$LDAP_BIND_PASSWORD"; }
