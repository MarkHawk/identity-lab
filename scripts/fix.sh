#!/usr/bin/env bash
# Revert a failure scenario.   scripts/fix.sh <scenario>|--all
# Idempotent: fixing a healthy scenario changes nothing.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
require docker curl jq openssl
[[ $# -eq 1 ]] || { echo "usage: $0 <scenario>|--all"; echo "scenarios:"; scenario_names | sed 's/^/  /'; exit 2; }
load_env

# fix_one <scenario> [quiet] -- quiet skips the per-scenario confirm hint (--all).
fix_one() {
  local name="$1" quiet="${2:-}" state detail
  load_scenario "$name"
  IFS=$'\t' read -r state detail < <(scenario_detect)
  case "$state" in
    healthy) ok "$name is already healthy -- nothing to do"; [[ -n "$quiet" ]] || print_confirm "$name"; return 0 ;;
    # A detail starting "stale:" means leftovers that scenario_fix clears (a
    # browser state file or session with nothing to match it), not a lab that
    # can't be read: go on and fix it.
    unknown) if [[ "$detail" == stale:* ]]; then warn "$name: $detail"; else die "cannot determine state of $name: $detail"; fi ;;
  esac
  log "fixing $name"
  scenario_fix
  IFS=$'\t' read -r state detail < <(scenario_detect)
  [[ "$state" == healthy ]] || die "$name is still not healthy (state: $state, $detail)"
  ok "$name is healthy: $detail"
  [[ -n "$quiet" ]] || print_confirm "$name"
}

if [[ "$1" == "--all" ]]; then
  for n in $(scenario_names); do fix_one "$n" quiet; done
  echo
  echo "    Confirm recovery: in a NEW private window, log in as alice at"
  echo "    $(app_url saml) and $(app_url oidc); scripts/status.sh should show every scenario healthy."
else
  fix_one "$1"
fi
