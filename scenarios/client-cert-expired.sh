# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The partner system's client certificate for the proxy's mutual-TLS route
# (:8189) expired yesterday: nobody renewed it, because nothing was watching
# its date. The client still sends it, and nginx, which checks it against
# the lab CA, rejects it: 400 "The SSL certificate error", which nginx
# calls 495 internally. A request without any certificate fails the same
# way to the user (400), for a different reason (client-cert-missing).
SCENARIO_SUMMARY="the mTLS client's certificate has expired (nginx 495)"
SCENARIO_RUNBOOK="runbooks/18-client-cert.md"
SCENARIO_APP=mtls
SCENARIO_USER=partner-client
SCENARIO_UNAFFECTED="oidc-proxy alice"
SCENARIO_EXPECT="The SSL certificate error"
SCENARIO_SEEN_AT="on nginx's \"400 Bad Request\" page, after a TLS handshake that succeeded"
SCENARIO_LOG='proxy " 400 [0-9]+ host=[^ ]*:8189 client_dn="CN=partner-client" .*ssl_client_verify=FAILED:certificate has expired$'
SCENARIO_ALSO="curl with the expired certificate gets 400 too, and the proxy's error log says: (10:certificate has expired)"

scenario_detect() {
  local cert
  cert="$(mtls_cert_check)"
  case "$cert" in
    none)    printf 'healthy\tthe client has no certificate, so none that is expired (see client-cert-missing)\n' ;;
    valid)   printf 'healthy\tthe client certificate verifies (%s)\n' "$(mtls_cert_summary)" ;;
    invalid*) printf 'broken\tthe client certificate does not verify: %s (%s)\n' "${cert#*$'\t'}" "$(mtls_cert_summary)" ;;
  esac
}

# Issued by the lab CA, so the only thing wrong with it is the date.
scenario_break() {
  local tmp
  tmp="$(mktemp -d)"
  issue_cert "$tmp/client" partner-client "-397 days" "-1 day" client
  mtls_client_set "$tmp/client.crt" "$tmp/client.key"
  rm -rf "$tmp"
}
scenario_fix() { mtls_client_restore; }

# shellcheck disable=SC2329  # invoked by scripts/test.sh while broken
scenario_also_check() {
  local code logs
  code="$(mtls_call)" || true
  echo "curl with the expired client certificate: HTTP $code"
  [[ "$code" == 400 ]] || { echo "expected HTTP 400"; return 1; }
  logs="$(compose logs --no-log-prefix --since 2m proxy)"
  grep -m1 -F 'client SSL certificate verify error: (10:certificate has expired) while reading client request headers' <<<"$logs" \
    || { echo "no '(10:certificate has expired)' line in the proxy's log"; return 1; }
}
