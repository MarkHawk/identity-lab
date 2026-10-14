#!/usr/bin/env bash
# End-to-end test of the lab.
#
#   scripts/test.sh            build, start (or reuse) the lab, run all checks
#   scripts/test.sh --fresh    first remove the lab's containers AND its volumes
#                              (Keycloak database, directory, NAS secret), so
#                              everything is re-created from the repo and .env
#   scripts/test.sh --down     stop the lab afterwards (keeps the volume)
#
# Checks: service health and an LDAP bind as Keycloak's service account; a
# scripted browser login to each app as a local user (alice) and an LDAP user
# (dave); a RADIUS Access-Request from the NAS for dave (accepted) and with a
# wrong password (rejected); then for every scenario: break (twice), detected
# as broken, the expected error in the browser (or in the NAS's output, for
# RADIUS scenarios), the expected log line, a user outside the
# blast radius still logging in (where a scenario names one), fix (twice),
# detected healthy, and a successful login again. Failed checks don't stop the run; the exit status
# is the number of failed checks (capped at 100). Evidence (screenshots,
# page HTML, full output) goes to test-results/.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
require docker curl jq openssl

FRESH=0 DOWN=0
for arg in "$@"; do
  case "$arg" in
    --fresh) FRESH=1 ;;
    --down)  DOWN=1 ;;
    *) die "unknown option: $arg (use --fresh, --down)" ;;
  esac
done

RESULTS="$LAB_ROOT/test-results"
mkdir -p "$RESULTS"
LOG="$RESULTS/test.log"
: >"$LOG"
declare -a NAMES=() OUTCOMES=()
FAILED=0

# check <description> <command...> -- run, record, show output on failure.
check() {
  local name="$1"; shift
  local out rc=0
  printf '%s\n=== %s\n$ %s\n' "" "$name" "$*" >>"$LOG"
  out="$("$@" 2>&1)" || rc=$?
  printf '%s\n(exit %d)\n' "$out" "$rc" >>"$LOG"
  NAMES+=("$name")
  if (( rc == 0 )); then
    OUTCOMES+=(PASS); ok "$name"
  else
    OUTCOMES+=(FAIL); FAILED=$((FAILED + 1))
    printf '%sFAIL%s %s\n' "$C_RED" "$C_OFF" "$name"
    printf '%s\n' "$out" | tail -n 15 | sed 's/^/       /'
  fi
  return 0
}

# shellcheck disable=SC2329  # invoked indirectly: check "<name>" expect_state ...
expect_state() { [[ "$("$LAB_ROOT/scripts/status.sh" "$1")" == "$2" ]] || { echo "state is not $2"; "$LAB_ROOT/scripts/status.sh" | tail -n 6; return 1; }; }
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" browser ...
browser()      { compose run --rm tests "$@"; }
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" browser_as ...
browser_as()   { local user="$1"; shift; compose run --rm -e E2E_USER="$user" tests "$@"; }
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" radius_login ...
radius_login() { # <user> <password> <text nas-auth must print>; the password goes in on stdin
  local out
  out="$(printf '%s' "$2" | compose exec -T nas nas-auth "$1" 2>&1)" || true
  echo "$out"
  grep -qF -- "$3" <<<"$out" || { echo "expected: $3"; return 1; }
}
# login_as <user> <saml|oidc|radius> --expect ok | --expect-error <text>
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" login_as ...
login_as()     {
  local user="$1" app="$2"; shift 2
  [[ "$app" == radius ]] || { browser_as "$user" "$app" "$@"; return; }
  case "$1" in
    --expect)       radius_login "$user" "$DEMO_PASSWORD" "nas: Access-Accept" ;;
    --expect-error) radius_login "$user" "$DEMO_PASSWORD" "$2" ;;
  esac
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" ldap_bind_ok
ldap_bind_ok() { # the by-hand test from runbook 04; the password goes in on stdin
  local out
  out="$(printf '%s' "$LDAP_BIND_PASSWORD" | compose exec -T ldap ldapwhoami -x -H ldaps://ldap:1636 \
    -D cn=keycloak-svc,ou=services,dc=idlab,dc=example -y /dev/stdin 2>&1)" || { echo "$out"; return 1; }
  echo "$out"
  [[ "$out" == "dn:cn=keycloak-svc,ou=services,dc=idlab,dc=example" ]]
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" log_has ...
log_has()      { # <since> <service> <pattern>
  # Read the logs first: piping into grep -m1 would SIGPIPE compose when the
  # match isn't near the end, and pipefail would turn a match into a failure.
  local logs
  logs="$(compose logs --no-log-prefix --since "$1" "$2")"
  grep -E -m1 -- "$3" <<<"$logs" \
    || { echo "no log line matching /$3/ in $2 since $1"; return 1; }
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" healthy ...
healthy()      {
  local st
  st="$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q "$1")")"
  [[ "$st" == healthy ]] || { echo "$1 health is $st"; return 1; }
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" http_ok ...
http_ok()      { kc_curl -o /dev/null --resolve "$LAB_HOST:$2:127.0.0.1" "https://$LAB_HOST:$2$1"; }
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" issuer_ok ...
issuer_ok()    {
  local iss
  iss="$(kc_curl "https://$LAB_HOST:$KC_PORT/realms/$REALM/.well-known/openid-configuration" | jq -r .issuer)"
  [[ "$iss" == "https://$LAB_HOST:$KC_PORT/realms/$REALM" ]] || { echo "issuer is $iss"; return 1; }
}

# --- Bring the lab up -----------------------------------------------------------
[[ -f "$ENV_FILE" ]] || "$LAB_ROOT/scripts/setup.sh"
load_env
log "LAB_HOST=$LAB_HOST"

if (( FRESH )); then
  log "--fresh: removing lab containers and the Keycloak database volume"
  compose --profile test down -v --remove-orphans
fi

log "building images"
compose --profile test build >>"$LOG" 2>&1 || { tail -n 30 "$LOG"; die "image build failed"; }
log "starting the lab (waiting for health checks)"
compose up -d --wait --wait-timeout 300 >>"$LOG" 2>&1 \
  || { compose ps; compose logs --tail 40 >>"$LOG" 2>&1; die "lab did not become healthy (see $LOG)"; }

# Onboarding: pin the IdP certificate on the SP, and start from a clean state
# in case a scenario was left broken.
"$LAB_ROOT/scripts/pin-idp-cert.sh" >>"$LOG" 2>&1 || die "could not pin the IdP certificate"
"$LAB_ROOT/scripts/fix.sh" --all >>"$LOG" 2>&1 || die "could not reset scenarios to healthy (see $LOG)"

# --- Health -----------------------------------------------------------------------
log "health"
for svc in postgres ldap keycloak saml-sp oidc-rp radius nas; do
  check "health: $svc container healthy" healthy "$svc"
done
check "health: Keycloak issuer is https://$LAB_HOST:$KC_PORT/realms/$REALM" issuer_ok
check "health: SAML SP /healthz over verified TLS" http_ok /healthz "$SAML_SP_PORT"
check "health: OIDC RP /healthz over verified TLS" http_ok /healthz "$OIDC_RP_PORT"
check "health: LDAP bind as keycloak-svc (ldapwhoami over LDAPS)" ldap_bind_ok

# --- Baseline logins --------------------------------------------------------------
log "baseline logins"
check "login: SAML SP (alice)" browser saml --expect ok
check "login: OIDC RP (alice)" browser oidc --expect ok
check "login: SAML SP (dave, from LDAP)" browser_as dave saml --expect ok
check "login: OIDC RP (dave, from LDAP)" browser_as dave oidc --expect ok
check "login: RADIUS Access-Accept (dave, from LDAP)" radius_login dave "$DEMO_PASSWORD" "nas: Access-Accept"
check "login: RADIUS Access-Reject (dave, wrong password)" radius_login dave "not-the-demo-password" "nas: Access-Reject"

# --- Scenarios --------------------------------------------------------------------
for name in $(scenario_names); do
  load_scenario "$name"
  user="${SCENARIO_USER:-alice}"
  log "scenario: $name"
  check "$name: break"                         "$LAB_ROOT/scripts/break.sh" "$name"
  check "$name: detected as broken"            expect_state "$name" broken
  check "$name: break again is a no-op"        "$LAB_ROOT/scripts/break.sh" "$name"
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  check "$name: $user sees \"$SCENARIO_EXPECT\"" login_as "$user" "$SCENARIO_APP" --expect-error "$SCENARIO_EXPECT"
  check "$name: log shows ${SCENARIO_LOG#* }"  log_has "$since" "${SCENARIO_LOG%% *}" "${SCENARIO_LOG#* }"
  if [[ -n "${SCENARIO_UNAFFECTED:-}" ]]; then
    read -r ua_app ua_user <<<"$SCENARIO_UNAFFECTED"
    check "$name: $ua_user still logs in to $ua_app while broken" login_as "$ua_user" "$ua_app" --expect ok
  fi
  check "$name: fix"                           "$LAB_ROOT/scripts/fix.sh" "$name"
  check "$name: detected as healthy"           expect_state "$name" healthy
  check "$name: fix again is a no-op"          "$LAB_ROOT/scripts/fix.sh" "$name"
  check "$name: login works again ($user)"     login_as "$user" "$SCENARIO_APP" --expect ok
done

# --- Summary ----------------------------------------------------------------------
echo
log "summary"
for i in "${!NAMES[@]}"; do
  [[ "${OUTCOMES[$i]}" == PASS ]] && c="$C_GRN" || c="$C_RED"
  printf '  %s%s%s  %s\n' "$c" "${OUTCOMES[$i]}" "$C_OFF" "${NAMES[$i]}"
done
echo
echo "  ${#NAMES[@]} checks, $(( ${#NAMES[@]} - FAILED )) passed, $FAILED failed. Full log: $LOG"

if (( DOWN )); then
  log "stopping the lab"
  compose --profile test down >>"$LOG" 2>&1
fi
exit $(( FAILED > 100 ? 100 : FAILED ))
