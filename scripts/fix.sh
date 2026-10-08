#!/usr/bin/env bash
# Revert a failure scenario.   scripts/fix.sh <scenario>|--all
# Idempotent: fixing a healthy scenario changes nothing.
source "$(dirname "$0")/lib.sh"
require docker curl jq openssl
[[ $# -eq 1 ]] || { echo "usage: $0 <scenario>|--all"; echo "scenarios:"; scenario_names | sed 's/^/  /'; exit 2; }
load_env

fix_one() {
  local name="$1" state detail
  load_scenario "$name"
  IFS=$'\t' read -r state detail < <(scenario_detect)
  case "$state" in
    healthy) ok "$name is already healthy -- nothing to do"; return 0 ;;
    unknown) die "cannot determine state of $name: $detail" ;;
  esac
  log "fixing $name"
  scenario_fix
  IFS=$'\t' read -r state detail < <(scenario_detect)
  [[ "$state" == healthy ]] || die "$name is still not healthy (state: $state, $detail)"
  ok "$name is healthy: $detail"
}

if [[ "$1" == "--all" ]]; then
  for n in $(scenario_names); do fix_one "$n"; done
else
  fix_one "$1"
fi
