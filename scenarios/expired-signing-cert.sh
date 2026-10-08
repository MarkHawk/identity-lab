# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The IdP's SAML signing certificate -- the one pinned on the SP at
# onboarding -- reaches its notAfter date. The SP refuses an expired IdP
# certificate, so every SAML login fails.
#
# Keycloak 26 refuses to import an already-expired certificate, and once a
# certificate lapses it demotes that key and signs with a generated
# "fallback-RS256" key instead. So the scenario reproduces what happens in
# real life: a certificate that was valid when installed and pinned expires.
#
# break: add an RS256 key whose CA-signed certificate expires 20 seconds
#        later, make it the realm's only enabled RS256 key, pin it on the SP
#        (as at onboarding), and wait for it to expire.
# fix:   rotate -- remove the expired, retired and fallback keys, add a new
#        CA-signed key valid for a year, and re-pin the SP from metadata.
SCENARIO_SUMMARY="IdP SAML signing certificate pinned on the SP has expired"
SCENARIO_RUNBOOK="runbooks/01-expired-signing-cert.md"
SCENARIO_APP=saml
SCENARIO_EXPECT="IdP signing certificate expired"
SCENARIO_SEEN_AT="on the SAML SP error page after you sign in"
SCENARIO_LOG='saml-sp saml_login_failed reason=idp_cert_expired'

_esc_name="idlab-expiring-signing-key"
_esc_ttl=20
_esc_dir="$STATE_DIR/expired-signing-cert"
_esc_key_type="org.keycloak.keys.KeyProvider"

# RS256 key providers (generated, imported or fallback) in the realm.
_esc_rs256() {
  kc_api GET "/$REALM/components?type=$_esc_key_type" | jq -c '
    [ .[] | select(.providerId == "rsa" or .providerId == "rsa-generated")
          | select((.config.algorithm // ["RS256"])[0] == "RS256") ]'
}

_esc_add_key() { # <component name> <priority> <key file> <cert file>
  local realm_id
  realm_id="$(kc_api GET "/$REALM" | jq -r .id)"
  kc_api POST "/$REALM/components" "$(jq -nc \
    --arg name "$1" --arg prio "$2" --arg parent "$realm_id" --arg type "$_esc_key_type" \
    --rawfile key "$3" --rawfile cert "$4" '{
      name: $name, providerId: "rsa", providerType: $type, parentId: $parent,
      config: { priority: [$prio], enabled: ["true"], active: ["true"],
                algorithm: ["RS256"], privateKey: [$key], certificate: [$cert] } }')"
}

# Healthy only when the SP has a valid pinned certificate AND it is the one
# Keycloak is actually signing with.
scenario_detect() {
  local keys active pinned valid=() c newest=""
  keys="$(kc_api GET "/$REALM/keys" 2>/dev/null)" || { printf 'unknown\tKeycloak admin API unreachable\n'; return; }
  mapfile -t pinned < <(pinned_certs)
  (( ${#pinned[@]} )) || { printf 'broken\tSP has no pinned IdP certificate (run scripts/pin-idp-cert.sh)\n'; return; }
  for c in "${pinned[@]}"; do
    newest="$(b64_to_pem "$c" | openssl x509 -noout -enddate | cut -d= -f2)"
    b64_to_pem "$c" | openssl x509 -noout -checkend 0 >/dev/null && valid+=("$c")
  done
  (( ${#valid[@]} )) || { printf 'broken\tSP-pinned IdP signing cert EXPIRED %s\n' "$newest"; return; }
  active="$(jq -r '.active.RS256 as $k | .keys[] | select(.kid == $k) | .certificate' <<<"$keys")"
  [[ -n "$active" ]] || { printf 'broken\tIdP has no active RS256 signing key\n'; return; }
  for c in "${valid[@]}"; do
    if [[ "$c" == "$active" ]]; then
      printf 'healthy\tSP-pinned cert is the IdP active cert, valid until %s\n' \
        "$(b64_to_pem "$c" | openssl x509 -noout -enddate | cut -d= -f2)"
      return
    fi
  done
  printf 'broken\tIdP signs with a certificate the SP has not pinned\n'
}

scenario_break() {
  local c
  mkdir -p "$_esc_dir"
  trap 'rm -f "$_esc_dir/idp.key" "$_esc_dir/idp.crt"' RETURN
  issue_cert "$_esc_dir/idp" "idlab" "-1 year" "+$_esc_ttl seconds" signing
  _esc_add_key "$_esc_name" 1000 "$_esc_dir/idp.key" "$_esc_dir/idp.crt"
  # Only once the new key is in: disable every other RS256 key, so the
  # short-lived certificate is the one in metadata and the one Keycloak uses.
  while read -r c; do
    kc_api PUT "/$REALM/components/$(jq -r .id <<<"$c")" \
      "$(jq -c '.config.enabled = ["false"] | .config.active = ["false"]' <<<"$c")"
  done < <(_esc_rs256 | jq -c --arg n "$_esc_name" '.[] | select(.name != $n)')
  pin_idp_cert >/dev/null
  log "waiting ${_esc_ttl}s for the pinned signing certificate to expire"
  sleep $(( _esc_ttl + 2 ))
}

scenario_fix() {
  local c stamp
  # Remove the expiring key, keys that were retired (disabled) and the
  # fallback key Keycloak generates when no valid key is left.
  while read -r c; do
    kc_api DELETE "/$REALM/components/$(jq -r .id <<<"$c")"
  done < <(_esc_rs256 | jq -c --arg n "$_esc_name" \
             '.[] | select(.name == $n or .name == "fallback-RS256" or .config.enabled == ["false"])')
  # Rotate in a new CA-signed key if no enabled RS256 key is left.
  if [[ "$(_esc_rs256 | jq 'length')" == 0 ]]; then
    stamp="$(date -u +%Y%m%d%H%M%S)"
    mkdir -p "$_esc_dir"
    trap 'rm -f "$_esc_dir/idp.key" "$_esc_dir/idp.crt"' RETURN
    issue_cert "$_esc_dir/idp" "idlab" "-1 hour" "+1 year" signing
    _esc_add_key "idlab-signing-$stamp" 100 "$_esc_dir/idp.key" "$_esc_dir/idp.crt"
  fi
  # Re-exchange metadata: pin the new certificate on the SP.
  pin_idp_cert >/dev/null
}
