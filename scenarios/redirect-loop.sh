# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# Someone adds a request ID for tracing to the edge OIDC RP's location in
# the proxy: one proxy_set_header line. nginx then stops inheriting the
# server's proxy_set_header lines in that location, X-Forwarded-Proto among
# them. TLS ends at the proxy and the app gets plain HTTP, so without the
# header it believes the browser used http, and redirects to its https URL:
# the URL the browser is already on. The browser follows the redirect until
# it gives up with "too many redirects". Every other route is unaffected.
SCENARIO_SUMMARY="the proxy stops sending X-Forwarded-Proto to an app that forces HTTPS"
SCENARIO_RUNBOOK="runbooks/15-redirect-loop.md"
SCENARIO_APP=oidc-edge
SCENARIO_UNAFFECTED="oidc-proxy alice"
SCENARIO_EXPECT="ERR_TOO_MANY_REDIRECTS"
SCENARIO_SEEN_AT="on the browser's own error page (\"This page isn't working ... redirected you too many times\"), before any login"
SCENARIO_LOG='oidc-rp-edge event=force_https path=/ scheme=http x_forwarded_proto=-'

_rl_file=edge-location.conf

# What the app answers through the proxy decides it: a redirect to the very
# URL that was asked for is the loop. The include file is the detail.
scenario_detect() {
  local file live url="https://$LAB_HOST:$PROXY_EDGE_RP_PORT/" got
  file="$(proxy_conf_detect "$_rl_file" "")"
  [[ "${file%%$'\t'*}" == unknown ]] && { printf '%s\n' "$file"; return; }
  live="$(proxy_conf_live "$_rl_file" | tr '\n' ' ' | sed 's/;* *$//')"
  got="$(kc_curl -o /dev/null -w '%{http_code} %{redirect_url}' \
    --resolve "$LAB_HOST:$PROXY_EDGE_RP_PORT:127.0.0.1" "$url" 2>/dev/null)" \
    || { printf 'unknown\tthe edge OIDC RP is unreachable through the proxy\n'; return; }
  case "$got" in
    "200 ")     printf 'healthy\tGET %s answers 200 (%s: %s)\n' "$url" "$_rl_file" "${live:-no directives}" ;;
    "302 $url") printf 'broken\tGET %s redirects to itself (%s: %s)\n' "$url" "$_rl_file" "${live:-no directives}" ;;
    *)          printf 'unknown\tGET %s answers %s\n' "$url" "$got" ;;
  esac
}

scenario_break() {
  proxy_conf_set "$_rl_file" <<'CONF'
# Extra settings for the edge OIDC RP's location. Broken by scenarios/redirect-loop.sh:
# a request ID for tracing, added without repeating the server's headers.
proxy_set_header X-Request-ID $request_id;
CONF
}
scenario_fix() { proxy_conf_restore "$_rl_file"; }
