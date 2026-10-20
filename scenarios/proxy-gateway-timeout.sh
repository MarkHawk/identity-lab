# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The OIDC RP behind the proxy becomes slow to answer its login callback (as
# when the token endpoint, a database or another dependency behind it slows
# down): 10 seconds, against the 5-second proxy_read_timeout on that route.
# nginx gives up first and the user gets a 504, even though the app goes on
# to finish the login. The proxy's configuration is not touched, and the
# direct path (:8182) is a different container and stays fast.
SCENARIO_SUMMARY="the OIDC RP behind the proxy answers its callback slower than the proxy waits"
SCENARIO_RUNBOOK="runbooks/07-proxy-gateway-timeout.md"
SCENARIO_APP=oidc-proxy
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="504 Gateway Time-out"
SCENARIO_SEEN_AT="on an nginx error page about 5 seconds after you sign in"
SCENARIO_LOG='proxy upstream timed out \(110: Operation timed out\) while reading response header from upstream'

_pgt_file="$STATE_DIR/oidc-rp-proxied/callback-delay"
_pgt_slow=10
_pgt_timeout=5   # proxy_read_timeout for :8185 in proxy/nginx.conf

# What the app reads (its own mount of the file), not just the host copy.
scenario_detect() {
  local d
  [[ -n "$(compose ps -q --status running oidc-rp-proxied 2>/dev/null)" ]] \
    || { printf 'unknown\tthe oidc-rp-proxied container is not running\n'; return; }
  d="$(compose exec -T oidc-rp-proxied cat /var/lib/idlab/state/callback-delay 2>/dev/null)" \
    || { printf 'unknown\tcould not read the callback delay in oidc-rp-proxied\n'; return; }
  d="${d//[[:space:]]/}"
  if [[ "$d" == 0 ]]; then
    printf 'healthy\toidc-rp-proxied callback has no added delay (proxy_read_timeout %ss)\n' "$_pgt_timeout"
  else
    printf 'broken\toidc-rp-proxied callback takes an extra %ss (proxy_read_timeout %ss)\n' "$d" "$_pgt_timeout"
  fi
}

scenario_break() { echo "$_pgt_slow" >"$_pgt_file"; }
scenario_fix()   { echo 0 >"$_pgt_file"; }
