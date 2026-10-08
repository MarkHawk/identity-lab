#!/usr/bin/env bash
# Show service health and the live state of every scenario.
#   scripts/status.sh             human-readable table
#   scripts/status.sh <scenario>  print just broken|healthy|unknown (for scripts)
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
require docker curl jq openssl
load_env

if [[ $# -eq 1 ]]; then
  load_scenario "$1"
  scenario_state
  exit 0
fi

log "services"
compose ps --format '  {{.Service}}\t{{.Status}}' | column -t -s $'\t'
echo
log "scenarios (detected from live state)"
for name in $(scenario_names); do
  load_scenario "$name"
  IFS=$'\t' read -r state detail < <(scenario_detect)
  case "$state" in
    healthy) colour="$C_GRN" ;; broken) colour="$C_RED" ;; *) colour="$C_YLW" ;;
  esac
  printf '  %-24s %s%-8s%s %s\n' "$name" "$colour" "$state" "$C_OFF" "$detail"
done
echo
echo "  Keycloak  https://$LAB_HOST:$KC_PORT/admin/   SAML SP  https://$LAB_HOST:$SAML_SP_PORT/   OIDC RP  https://$LAB_HOST:$OIDC_RP_PORT/"
