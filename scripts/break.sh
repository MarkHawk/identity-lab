#!/usr/bin/env bash
# Put the lab into a failure scenario.   scripts/break.sh <scenario>
# Idempotent: breaking an already-broken scenario changes nothing.
source "$(dirname "$0")/lib.sh"
require docker curl jq openssl
[[ $# -eq 1 ]] || { echo "usage: $0 <scenario>"; echo "scenarios:"; scenario_names | sed 's/^/  /'; exit 2; }
load_env
load_scenario "$1"

IFS=$'\t' read -r state detail < <(scenario_detect)
case "$state" in
  broken)  ok "$1 is already broken -- nothing to do ($detail)"; exit 0 ;;
  unknown) die "cannot determine state of $1: $detail" ;;
esac

log "breaking $1: $SCENARIO_SUMMARY"
scenario_break
IFS=$'\t' read -r state detail < <(scenario_detect)
[[ "$state" == broken ]] || die "$1 did not break (state: $state, $detail)"
ok "$1 is broken: $detail"
echo "    Reproduce: log in to the ${SCENARIO_APP^^} app. Runbook: $SCENARIO_RUNBOOK"
