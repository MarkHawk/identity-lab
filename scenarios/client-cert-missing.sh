# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# A partner system calls the proxy's mutual-TLS route (:8189) with a client
# certificate. It is redeployed, and its certificate and key don't come
# with it (a secret mount left out of the new deployment), so it connects
# without one. nginx completes the TLS handshake anyway, then refuses the
# request: 400 "No required SSL certificate was sent", which nginx calls
# 496 internally. Every other route through the proxy is unaffected.
SCENARIO_SUMMARY="the mTLS client lost its certificate and connects without one (nginx 496)"
SCENARIO_RUNBOOK="runbooks/18-client-cert.md"
SCENARIO_APP=mtls
SCENARIO_USER=partner-client
SCENARIO_UNAFFECTED="oidc-proxy alice"
SCENARIO_EXPECT="No required SSL certificate was sent"
SCENARIO_SEEN_AT="on nginx's \"400 Bad Request\" page, after a TLS handshake that succeeded"
SCENARIO_LOG='proxy " 400 [0-9]+ host=[^ ]*:8189 .*ssl_client_verify=NONE$'
SCENARIO_ALSO="curl gets 400 too, and the proxy's error log says: client sent no required SSL certificate"

scenario_detect() {
  local cert
  cert="$(mtls_cert_check)"
  case "$cert" in
    none) printf 'broken\tthe client has no certificate in %s\n' "${MTLS_CLIENT_DIR#"$LAB_ROOT"/}" ;;
    *)    printf 'healthy\tthe client has a certificate (%s; %s)\n' "$(mtls_cert_summary)" "${cert%%$'\t'*}" ;;
  esac
}

scenario_break() { rm -f "$MTLS_CLIENT_DIR/client.crt" "$MTLS_CLIENT_DIR/client.key"; }
scenario_fix()   { mtls_client_restore; }

# shellcheck disable=SC2329  # invoked by scripts/test.sh while broken
scenario_also_check() {
  local code logs
  code="$(mtls_call)" || true
  echo "curl without a client certificate: HTTP $code"
  [[ "$code" == 400 ]] || { echo "expected HTTP 400"; return 1; }
  logs="$(compose logs --no-log-prefix --since 2m proxy)"
  grep -m1 -F 'client sent no required SSL certificate while reading client request headers' <<<"$logs" \
    || { echo "no 'client sent no required SSL certificate' line in the proxy's log"; return 1; }
}
