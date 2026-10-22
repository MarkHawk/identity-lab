# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The API's CORS setting (the Access-Control-Allow-Origin it sends) is
# changed to the RP's origin with a trailing slash, as copied from the
# browser's address bar. An origin has no path, so the browser compares
# https://LAB_HOST:8182 with https://LAB_HOST:8182/ and refuses. The API's
# preflight is answered separately (as by a gateway) and still allows the
# call, so the browser sends it, the API validates the token, answers 200
# and logs a success. The browser then withholds the response from the page,
# which only sees "Failed to fetch"; the reason is in the browser console.
# The RP's own server-side call to the API is unaffected: CORS is a browser rule.
SCENARIO_SUMMARY="the API's Access-Control-Allow-Origin has a trailing slash: browsers block its answers"
SCENARIO_RUNBOOK="runbooks/19-cors-blocked.md"
SCENARIO_APP=oidc-cors
SCENARIO_UNAFFECTED="oidc-api alice"
SCENARIO_EXPECT="is not equal to the supplied origin"
SCENARIO_SEEN_AT="in the browser's developer console (F12) after \"Call the API from the browser\" on the debug page; the page itself only says: API call from the browser failed: TypeError: Failed to fetch"
SCENARIO_LOG='api event=api_request_ok .* origin=https://[^ ]+:[0-9]+ cors_allow_origin=https://[^ ]+:[0-9]+/$'
SCENARIO_ALSO="the API answered the browser's preflight too: it logs success while the browser blocks the response"

_cb_file="$STATE_DIR/api/cors-allow-origin"
_cb_origin() { echo "https://$LAB_HOST:$OIDC_RP_PORT"; }

# What the API really sends to a request from the RP's origin decides it.
# /healthz gets the same header as /v1/whoami, without a token rejection in
# the API's log for every status check.
_cb_live() {
  curl -sS -o /dev/null -D - --cacert "$CERTS_DIR/ca.crt" --resolve "$LAB_HOST:$API_PORT:127.0.0.1" \
    -H "Origin: $(_cb_origin)" "https://$LAB_HOST:$API_PORT/healthz" \
    | tr -d '\r' | sed -n 's/^[Aa]ccess-[Cc]ontrol-[Aa]llow-[Oo]rigin: //p'
}

scenario_detect() {
  local allow
  allow="$(_cb_live 2>/dev/null)" || { printf 'unknown\tthe API is unreachable\n'; return; }
  if [[ "$allow" == "$(_cb_origin)" ]]; then
    printf 'healthy\tthe API sends Access-Control-Allow-Origin: %s\n' "$allow"
  else
    printf 'broken\tthe API sends Access-Control-Allow-Origin: %s for origin %s\n' "${allow:-(none)}" "$(_cb_origin)"
  fi
}

# Re-read by the API on every request: no restart, like a config reload.
_cb_set() { printf '%s\n' "$1" >"$_cb_file.tmp" && chmod 644 "$_cb_file.tmp" && mv "$_cb_file.tmp" "$_cb_file"; }
scenario_break() { _cb_set "$(_cb_origin)/"; }
scenario_fix()   { _cb_set "$(_cb_origin)"; }

# shellcheck disable=SC2329  # invoked by scripts/test.sh while broken
scenario_also_check() {
  local logs
  # The browser's calls (its Referer is the RP's page), not the RP's own.
  logs="$(compose logs --no-log-prefix --since 1m api)"
  grep -m1 -E "event=api_cors_preflight origin=$(_cb_origin) method=GET headers=authorization" <<<"$logs" \
    || { echo "no api_cors_preflight line from $(_cb_origin)"; return 1; }
  grep -m1 -E "\"GET /v1/whoami HTTP/1.1\" 200 [0-9]+ \"$(_cb_origin)/[^\"]*\" \"Mozilla" <<<"$logs" \
    || { echo "no GET /v1/whoami 200 from the browser in the API's access log"; return 1; }
}
