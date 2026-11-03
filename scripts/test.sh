#!/usr/bin/env bash
# End-to-end test of the lab.
#
#   scripts/test.sh            build, start (or reuse) the lab, run all checks
#   scripts/test.sh --fresh    first remove the lab's containers AND its volumes
#                              (Keycloak database, directory, NAS secret), so
#                              everything is re-created from the repo and .env
#   scripts/test.sh --down     stop the lab afterwards (keeps the volume)
#
# Checks: service health and an LDAP bind as Keycloak's service account;
# Keycloak's issuer directly and through the reverse proxy, and that it ignores
# X-Forwarded-* headers that don't come from the proxy; that the OIDC RP
# behind the Squid egress proxy has no route to Keycloak without it; that
# the API answers a call with no token or a malformed one with a 401 and the
# right WWW-Authenticate challenge; a scripted browser login to each app,
# directly, through the reverse proxy (also to the OIDC RP it reaches over
# plain HTTP) and (OIDC) through the egress proxy, as a local user (alice)
# and an LDAP user (dave), with the egress RP's back channel in Squid's log;
# the direct OIDC RP calling the API with its access token (the API logging
# the token's iat and exp), and from the browser (a cross-origin call, so
# CORS applies, after a preflight the API allows), and handing out the raw
# token on /debug/access-token; the proxy's mutual-TLS route accepting the
# partner client's certificate (curl and browser) and refusing a request
# without one; a RADIUS Access-Request from the NAS
# for dave (accepted) and with a wrong password (rejected); then for every scenario: break (twice), detected
# as broken, the expected error in the browser (or in the NAS's output, for
# RADIUS scenarios), the expected log line, a user outside the
# blast radius still logging in (where a scenario names one), any extra check
# the scenario defines (scenario_also_check), fix (twice),
# detected healthy, and a successful login again; last, that no secret
# from .env, authorisation code, OAuth state or other one-time login value
# (nonce, code_challenge, Signature, session_code, client_data) appears in
# any container's log, that the proxy's log has each of those last five
# masked (so the check had something to see), no JWT (access or ID token) in any container's log,
# saved page evidence or test.log, and no private key in any container's log or test.log. Failed checks don't stop the run; the exit status
# is the number of failed checks (capped at 100). Evidence (screenshots,
# page HTML, full output) goes to test-results/; values of secrets from .env
# are replaced with <redacted> in test.log.
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

# Values of every *PASSWORD, *SECRET and *SECRET_KEY in .env, filled in after
# load_env. Nothing that reaches test.log or the terminal may contain them.
declare -a SECRETS=()
# The MFA users' TOTP secrets (*_TOTP_SECRET, base32), in upper and lower
# case. They're in SECRETS too, but are redacted with their own marker, so
# the leak check can tell that one reached test.log.
declare -a TOTP_SECRETS=()
TOTP_MARK="<redacted-totp-""secret>"   # split, so this file never holds the marker itself
load_secrets() {
  local v
  while read -r v; do
    [[ -n "${!v:-}" ]] && SECRETS+=("${!v}")
    [[ -n "${!v:-}" && "$v" == *_TOTP_SECRET ]] && TOTP_SECRETS+=("${!v}" "${!v,,}")
  done < <(sed -n 's/^\([A-Z_]*\(PASSWORD\|SECRET\|SECRET_KEY\)\)=.*/\1/p' "$ENV_FILE")
  return 0
}

# redact <text> -- print text with every secret value replaced.
redact() {
  local s="$1" v
  for v in "${TOTP_SECRETS[@]}"; do s="${s//"$v"/$TOTP_MARK}"; done
  for v in "${SECRETS[@]}"; do s="${s//"$v"/<redacted>}"; done
  printf '%s' "$s"
}

# Backstop for output that doesn't go through check (build, compose, fix.sh):
# rewrite the whole log with secrets replaced when the script exits.
# shellcheck disable=SC2329  # invoked by the EXIT trap
redact_log() {
  [[ -f "$LOG" && ${#SECRETS[@]} -gt 0 ]] || return 0
  local all
  all="$(<"$LOG")"
  { redact "$all"; echo; } >"$LOG.tmp" && mv "$LOG.tmp" "$LOG"
}
# One-time codes submitted during the run, one per line, for the leak check.
# Outside test-results/, mode 0600, deleted on exit. Never printed.
CODES_FILE="$(umask 077; mktemp)"
# shellcheck disable=SC2329  # invoked by the EXIT trap
on_exit() { redact_log; rm -f "$CODES_FILE"; }
trap on_exit EXIT

# check <description> <command...> -- run, record, show output on failure.
# Pass secrets by name (see radius_login), never as arguments: the command
# line is logged.
check() {
  local name="$1"; shift
  local out rc=0
  printf '%s\n=== %s\n$ %s\n' "" "$name" "$(redact "$*")" >>"$LOG"
  out="$("$@" 2>&1)" || rc=$?
  out="$(redact "$out")"
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
radius_login() { # <user> <demo|wrong> <text nas-auth must print>; the password goes in on stdin
  local out pw code=""
  case "$2" in
    demo)  pw="$DEMO_PASSWORD" ;;
    wrong) pw="not-the-demo-password" ;;   # deliberately wrong, not a secret
    *)     echo "radius_login: password must be demo or wrong"; return 2 ;;
  esac
  # An MFA user also has a fresh code ready, as a second line, in case the
  # NAS asks for it after an Access-Challenge.
  if user_has_totp "$1"; then code="$(totp_for "$1" new)" || { echo "$code"; return 1; }; fi
  out="$(printf '%s\n%s\n' "$pw" "$code" | compose exec -T nas nas-auth "$1" 2>&1)" || true
  echo "$out"
  grep -qF -- "$3" <<<"$out" || { echo "expected: $3"; return 1; }
}
# login_as <user> <saml|oidc|radius> --expect ok | --expect-error <text>
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" login_as ...
login_as()     {
  local user="$1" app="$2"; shift 2
  if [[ "$app" != radius ]]; then
    # An MFA user also types a fresh code from the authenticator app.
    # A new starter sets one up, from scratch each time.
    if user_has_totp "$user"; then mfa_login "$user" "$app" new "$@"
    elif user_enrols_totp "$user"; then enrol_login "$user" "$app" "$@"
    else browser_as "$user" "$app" "$@"; fi
    return
  fi
  case "$1" in
    --expect)       radius_login "$user" demo "nas: Access-Accept" ;;
    --expect-error) radius_login "$user" demo "$2" ;;
  esac
}
# totp_for <user> <new|wrong|again> -- a one-time code from the user's
# authenticator app (again: the last one submitted), remembered in CODES_FILE.
# shellcheck disable=SC2329  # invoked by mfa_login, itself invoked indirectly
totp_for() {
  local code
  case "$2" in
    new|wrong) code="$(compose exec -T authenticator authenticator code "$1" "--$2" 2>&1)" ;;
    again)     code="$(tail -n 1 "$CODES_FILE")" ;;
    *)         echo "totp_for: new, wrong or again"; return 2 ;;
  esac
  [[ "$code" =~ ^[0-9]{6}$ ]] || { echo "the authenticator app gave no code: ${code:0:200}"; return 1; }
  [[ "$2" == again ]] || printf '%s\n' "$code" >>"$CODES_FILE"
  printf '%s\n' "$code"
}
# mfa_login <user> <app> <new|wrong|again> --expect ok | --expect-error <text>
# Password and one-time code, as an MFA user. The code reaches the browser on
# stdin, never as an argument, so it isn't in this log's command lines.
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" mfa_login ...
mfa_login() {
  local user="$1" app="$2" kind="$3" code; shift 3
  code="$(totp_for "$user" "$kind")" || { echo "$code"; return 1; }
  printf '%s\n' "$code" | compose run --rm -T -e E2E_USER="$user" -e E2E_OTP=stdin tests "$app" "$@"
}
# enrol_login <user> <app> --expect ok | --expect-error <text> -- a new
# starter's first login: the setup page, with an app that ignores the
# enrolment's algorithm and digits (e2e.py). The user is reset first.
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" enrol_login ...
enrol_login() {
  local user="$1" app="$2"; shift 2
  new_starter_reset "$user" || return 1
  compose run --rm -T -e E2E_USER="$user" -e E2E_ENROL=1 tests "$app" "$@" </dev/null
}
# radius_mfa <new|wrong|again> <text>... -- heidi over RADIUS: the demo
# password, then the code for the Access-Challenge. nas-auth must print
# every <text>.
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" radius_mfa ...
radius_mfa() {
  local kind="$1" code out t; shift
  code="$(totp_for heidi "$kind")" || { echo "$code"; return 1; }
  out="$(printf '%s\n%s\n' "$DEMO_PASSWORD" "$code" | compose exec -T nas nas-auth heidi 2>&1)" || true
  echo "$out"
  for t in "$@"; do grep -qF -- "$t" <<<"$out" || { echo "expected: $t"; return 1; }; done
}
# radius_forged_state -- an Access-Request with a valid code and a State the
# server never issued (no password round): it must be refused.
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" radius_forged_state
radius_forged_state() {
  local code out
  code="$(totp_for heidi new)" || { echo "$code"; return 1; }
  out="$(printf 'User-Name = "heidi"\nUser-Password = "%s"\nState = 0x%s\nNAS-Identifier = "nas"\nMessage-Authenticator = 0x00\n' \
    "$code" "$(openssl rand -hex 16)" | compose exec -T nas radclient -r 1 -t 3 -S /var/lib/nas/secret radius:1812 auth 2>&1)" || true
  grep -oE 'Received Access-[A-Za-z]+' <<<"$out" || echo "no reply"
  grep -qF 'Received Access-Reject' <<<"$out"
}
# radius_tampered <strip-ma|bad-ma> -- heidi's login through
# tests/radius-tamper.pl, which removes or changes the Access-Challenge's
# Message-Authenticator: nas-auth must not answer the challenge, and the
# server must get no second request.
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" radius_tampered ...
radius_tampered() {
  local code out since radius_log
  code="$(totp_for heidi new)" || { echo "$code"; return 1; }
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # shellcheck disable=SC2016  # expanded by the nas container's bash
  out="$(printf '%s\n%s\n' "$DEMO_PASSWORD" "$code" | compose exec -T nas bash -c \
    'perl -e "$1" "$2" </dev/null & sleep 1; NAS_RADIUS_SERVER=127.0.0.1:11812 nas-auth heidi; rc=$?; kill %1 2>/dev/null; exit $rc' \
    _ "$(<"$LAB_ROOT/tests/radius-tamper.pl")" "$1" 2>&1)" || true
  echo "$out"
  sleep 1
  radius_log="$(compose logs --no-log-prefix --since "$since" radius)"
  grep -qF 'radius-tamper: Access-Challenge relayed' <<<"$out" || { echo "the relay saw no challenge"; return 1; }
  if grep -qF 'answering the challenge' <<<"$out"; then echo "nas-auth answered a tampered challenge"; return 1; fi
  if grep -qE 'Login (OK|incorrect).*\[heidi\]' <<<"$radius_log"; then echo "the server got a second request"; return 1; fi
  case "$1" in
    strip-ma) grep -qF 'Access-Challenge without Message-Authenticator discarded' <<<"$out" ;;
    bad-ma)   grep -qF 'RADIUS server not responding' <<<"$out" ;;   # radclient drops a reply that doesn't verify
  esac
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" bf_failures_are ...
bf_failures_are() { # <user> <n> -- Keycloak's count of the user's failed logins
  local st
  st="$(bf_status "$1")" || return 1
  echo "$1: $(jq -c '{numFailures, disabled}' <<<"$st")"
  [[ "$(jq -r .numFailures <<<"$st")" == "$2" ]]
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" bf_clear_and_check ...
bf_clear_and_check() { bf_clear "$1" && bf_failures_are "$1" 0; }
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" authenticator_offline
authenticator_offline() { # the "phone" has no network: codes leave it only through exec
  local mode
  mode="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$(compose ps -q authenticator)")"
  echo "network mode: $mode"
  [[ "$mode" == none ]]
}
# --- Leak scanners --------------------------------------------------------------
# Each reads container logs on stdin and takes test.log and the saved pages
# as files, so the live checks and their self-test run the same code. They
# print counts and file names, never a secret or a code.
#
# A one-time code in container logs or pages counts only next to the name of
# an OTP field: how a submitted code would show in a request line, form body,
# debug dump or page. A bare six-digit number is too common there to flag:
# LDAP's qtime and etime alone write hundreds. In test.log, which nothing
# here should ever print a code to, any six digits on their own count.
# shellcheck disable=SC2329  # invoked by the scanners, themselves invoked indirectly
otp_code_re() { # <code>
  local key="(otp|totp|totp-password|user-password|passcode|one[-_ ]?time[-_ ]?(code|password))"
  printf '%s' "${key}[\"' ]*([:=]|value=)[\"' ]*$1([^0-9]|\$)|name=[\"']?(otp|totp)[\"']?[^>]*value=[\"']?$1([^0-9]|\$)"
}
# shellcheck disable=SC2329  # invoked by the scanners, themselves invoked indirectly
bare_code_re() { printf '%s' "(^|[^0-9A-Za-z])$1([^0-9A-Za-z]|\$)"; }

# scan_codes <codes-file> <test.log> [page...] -- 0 when no code is found.
# shellcheck disable=SC2329  # invoked by the scanners, themselves invoked indirectly
scan_codes() {
  local codes="$1" log="$2" text code n=0 hits=0 where; shift 2
  text="$(cat)"
  while read -r code; do
    [[ -n "$code" ]] || continue
    n=$((n + 1)) where=""
    if grep -qiE -- "$(otp_code_re "$code")" <<<"$text"; then where="a container log "; fi
    (( $# == 0 )) || where+="$(grep -liE -- "$(otp_code_re "$code")" "$@" 2>/dev/null | sed 's|.*/||' | tr '\n' ' ' || true)"
    if grep -qE -- "$(bare_code_re "$code")" "$log"; then where+="${log##*/} "; fi
    if [[ -n "$where" ]]; then hits=$((hits + 1)); echo "  code #$n found in: $where"; fi
  done < <(sort -u "$codes")
  echo "checked $n one-time code(s): $hits found"
  (( hits == 0 ))
}

# scan_totp_secrets <array-name> <test.log> [page...] -- 0 when no form of any
# secret in the named array is found. test.log is redacted as it's written,
# so a secret that reached it shows as TOTP_MARK.
# shellcheck disable=SC2329  # invoked by the scanners, themselves invoked indirectly
scan_totp_secrets() {
  local -n _forms="$1"; local log="$2" text v in_logs=0 files="" marked; shift 2
  text="$(cat)"
  for v in "${_forms[@]}"; do
    if grep -qF -- "$v" <<<"$text"; then in_logs=$((in_logs + 1)); fi
    files+="$(grep -lF -- "$v" "$@" "$log" 2>/dev/null || true)"$'\n'
  done
  files="$(grep . <<<"$files" | sed 's|.*/||' | sort -u || true)"
  marked="$(grep -cF -- "$TOTP_MARK" "$log" || true)"
  echo "checked ${#_forms[@]} form(s) of $(( ${#_forms[@]} / 2 )) TOTP secret(s): in container logs: $in_logs;" \
    "in saved pages or test.log: $(grep -c . <<<"$files" || true); redacted from test.log: $marked"
  [[ -z "$files" ]] || while read -r v; do printf '  %s\n' "$v"; done <<<"$files"
  (( in_logs == 0 && marked == 0 )) && [[ -z "$files" ]]
}

# scan_login_values <file> -- 0 when the file has no unmasked authorisation
# code, OAuth state or other one-time login value (client_data,
# session_code, nonce, ...), with the same patterns as the container logs.
# shellcheck disable=SC2329  # invoked by the checks below
scan_login_values() {
  local codes states others
  codes="$(grep -cE -- "$AUTH_CODE_RE" "$1" || true)"
  states="$(grep -cE -- "$STATE_RE" "$1" || true)"
  others="$(grep -cE -- "$ONE_TIME_RE" "$1" || true)"
  echo "${1##*/}: lines with an authorisation code: $codes; an OAuth state value: $states; an unmasked ${ONE_TIME_NAMES[*]}: $others"
  (( codes == 0 && states == 0 && others == 0 ))
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" testlog_free_of_login_values
testlog_free_of_login_values() { scan_login_values "$LOG"; }
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" totp_secret_nowhere
totp_secret_nowhere() { # no TOTP secret in any service's log, saved page or test.log
  compose logs --no-log-prefix 2>&1 | scan_totp_secrets TOTP_SECRETS "$LOG" "$RESULTS"/*.html
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" codes_nowhere
codes_nowhere() { # no submitted one-time code in any service's log, saved page or test.log
  [[ -s "$CODES_FILE" ]] || { echo "no one-time codes were submitted, so nothing to check"; return 1; }
  compose logs --no-log-prefix 2>&1 | scan_codes "$CODES_FILE" "$LOG" "$RESULTS"/*.html
}

# The scanners' self-test: a temporary directory laid out like the real
# evidence, with near misses that must not count, and (planted) a made-up
# TOTP secret and code where a leak would really appear. Nothing from .env.
SELFTEST_SECRET=MZXW6YTBOI2LKNJVGQ3TQOJQGEZDGNBV   # made up, base32, not a secret
SELFTEST_CODE=246810                              # made up
# shellcheck disable=SC2034  # read by scan_totp_secrets through a nameref
SELFTEST_FORMS=("$SELFTEST_SECRET" "${SELFTEST_SECRET,,}")
# shellcheck disable=SC2329  # invoked by the scanners, themselves invoked indirectly
selftest_dir() { # <dir> <clean|planted>
  local d="$1"
  printf '%s\n' "$SELFTEST_CODE" >"$d/codes"
  # Near misses: the same digits and letters, but nowhere a leak would be.
  cat >"$d/logs" <<LOG
conn=1012 op=3 RESULT tag=97 err=0 qtime=0.$SELFTEST_CODE etime=0.000412 nentries=1
192.0.2.10 - - [03/Nov/2026:19:35:46 +0000] "GET /realms/idlab/account HTTP/1.1" 200 $SELFTEST_CODE host=idlab.example
2026-11-03 19:35:46,345 WARN  [org.keycloak.events] type="LOGIN_ERROR", error="invalid_user_credentials", selected_credential_id="0f2c-$SELFTEST_CODE-a1"
LOG
  printf '<html><body><p>Ticket %s</p><input id="otp" name="otp" autocomplete="one-time-code"></body></html>\n' \
    "$SELFTEST_CODE" >"$d/page.html"
  printf '=== mfa: OIDC RP (grace, password and one-time code)\n$ mfa_login grace oidc new --expect ok\n[oidc] ended at stuck:https://idlab.example:8180/realms/idlab/login-actions/authenticate\n[oidc] PASS\n' >"$d/test.log"
  [[ "$2" == planted ]] || return 0
  # Leaks: a form body logged by a proxy, a debug dump, a page that kept the
  # typed value, and the script's own log.
  cat >>"$d/logs" <<LOG
192.0.2.10 - - [03/Nov/2026:19:35:47 +0000] "POST /realms/idlab/login-actions/authenticate?session_code=*** HTTP/1.1" 302 0 body="otp=$SELFTEST_CODE&login=Sign+In"
2026-11-03 19:35:47,101 DEBUG [org.keycloak.credential] stored otp credential secret=$SELFTEST_SECRET
LOG
  printf '<html><body><input id="otp" name="otp" autocomplete="one-time-code" value="%s"></body></html>\n' \
    "$SELFTEST_CODE" >"$d/page-planted.html"
  printf '<p>otpauth://totp/Identity%%20Lab:grace?secret=%s</p>\n' "${SELFTEST_SECRET,,}" >"$d/otpauth.html"
  printf '[oidc] typed %s\n' "$SELFTEST_CODE" >>"$d/test.log"
  # A browser stuck on a Keycloak login-action URL, printed whole.
  printf '[oidc] ended at stuck:https://idlab.example:8180/realms/idlab/login-actions/authenticate?execution=1f2e&client_id=oidc-rp&tab_id=Ab3_&client_data=eyJydSI6Imh0dHBzOi8vZXhhbXBsZSJ9\n' >>"$d/test.log"
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" leak_scanners_selftest ...
leak_scanners_selftest() { # <clean|planted> -- clean: both pass; planted: both report it
  local d out_c out_s out_l rc_c=0 rc_s=0 rc_l=0
  d="$(mktemp -d)"
  selftest_dir "$d" "$1"
  out_c="$(scan_codes "$d/codes" "$d/test.log" "$d"/*.html <"$d/logs")" || rc_c=$?
  out_s="$(scan_totp_secrets SELFTEST_FORMS "$d/test.log" "$d"/*.html <"$d/logs")" || rc_s=$?
  out_l="$(scan_login_values "$d/test.log")" || rc_l=$?
  rm -rf "$d"
  printf 'code scanner (exit %d):\n%s\nsecret scanner (exit %d):\n%s\nlogin value scanner (exit %d):\n%s\n' \
    "$rc_c" "$out_c" "$rc_s" "$out_s" "$rc_l" "$out_l"
  if [[ "$1" == clean ]]; then
    (( rc_c == 0 && rc_s == 0 && rc_l == 0 ))
  else
    # Every planted place must be named: a container log, the page, and test.log;
    # the secret in the logs and in the otpauth page.
    (( rc_c != 0 && rc_s != 0 && rc_l != 0 )) \
      && grep -qE 'found in: a container log .*page-planted\.html .*test\.log' <<<"$out_c" \
      && grep -qE 'in container logs: [1-9].*in saved pages or test\.log: 1;' <<<"$out_s" \
      && grep -qx '  otpauth.html' <<<"$out_s"
  fi
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" ldap_bind_ok
ldap_bind_ok() { # the by-hand test from runbook 04; the password goes in on stdin
  local out
  out="$(printf '%s' "$LDAP_BIND_PASSWORD" | compose exec -T ldap ldapwhoami -x -H ldaps://ldap:1636 \
    -D cn=keycloak-svc,ou=services,dc=idlab,dc=example -y /dev/stdin 2>&1)" || { echo "$out"; return 1; }
  echo "$out"
  [[ "$out" == "dn:cn=keycloak-svc,ou=services,dc=idlab,dc=example" ]]
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" egress_no_direct_route
egress_no_direct_route() { # the egress RP calls Keycloak with its proxy settings ignored
  local out
  # shellcheck disable=SC2016  # Python, not shell
  if out="$(compose exec -T oidc-rp-egress python -c '
import requests, sys
s = requests.Session(); s.trust_env = False
try:
    s.get("https://keycloak:8180/realms/idlab", timeout=5)
except requests.RequestException as e:
    print(type(e).__name__, e); sys.exit(1)
print("reached Keycloak without the proxy")' 2>&1)"; then
    echo "$out"; return 1
  fi
  echo "$out"
  grep -qF "Failed to resolve 'keycloak'" <<<"$out" || { echo "expected: Failed to resolve 'keycloak'"; return 1; }
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" egress_saved_log_has ...
egress_saved_log_has() { # <pattern> -- in the newest log fix.sh saved before recreating oidc-rp-egress
  local f
  f="$(find "$EGRESS_LOGS_DIR" -path '*/logs/oidc-rp-egress.log' 2>/dev/null | sort | tail -n 1)"
  [[ -n "$f" ]] || { echo "no saved log in $EGRESS_LOGS_DIR"; return 1; }
  echo "$f"
  grep -E -m1 -- "$1" "$f" || { echo "no line matching /$1/ in $f"; return 1; }
}
# An unmasked code= query value, or a Keycloak authorisation code anywhere
# (<uuid>.<session id>.<uuid>). The apps' and the proxy's logs mask them.
AUTH_CODE_RE='[?&]code=[^*&[:space:]"]|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[A-Za-z0-9_-]+\.[0-9a-f]{8}-'
# An unmasked OAuth state value: in a query string, or as the OIDC app's
# detail=state=... (not session_state, which the access logs mask anyway).
STATE_RE="(^|[?&= ])state=[^*&[:space:]\"']"
# Other one-time login values the proxy's logs mask (proxy/mask.awk), unmasked.
# client_data is base64 JSON holding the state, so STATE_RE can't see it.
ONE_TIME_NAMES=(nonce code_challenge Signature session_code client_data)
ONE_TIME_RE="[?&]($(IFS='|'; echo "${ONE_TIME_NAMES[*]}"))=[^*&[:space:]\"]"
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" logs_free_of_secrets
logs_free_of_secrets() { # no secret from .env, authorisation code or state value in any service's log
  local logs v n=0 codes states others
  logs="$(compose logs --no-log-prefix 2>&1)"
  for v in "${SECRETS[@]}"; do
    if grep -qF -- "$v" <<<"$logs"; then n=$((n + 1)); fi
  done
  codes="$(grep -cE -- "$AUTH_CODE_RE" <<<"$logs" || true)"
  states="$(grep -cE -- "$STATE_RE" <<<"$logs" || true)"
  others="$(grep -cE -- "$ONE_TIME_RE" <<<"$logs" || true)"
  echo "checked ${#SECRETS[@]} secret values against $(wc -l <<<"$logs") log lines: $n found"
  echo "log lines with an authorisation code: $codes; with an OAuth state value: $states"
  echo "log lines with an unmasked ${ONE_TIME_NAMES[*]}: $others"
  grep -E -m3 -- "$ONE_TIME_RE" <<<"$logs" | cut -c1-200 | sed 's/^/  /' || true
  (( n == 0 && codes == 0 && states == 0 && others == 0 ))
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" proxy_masked_seen
proxy_masked_seen() { # the logins put each of ONE_TIME_NAMES in the proxy's log, masked
  local logs name missing=()
  logs="$(compose logs --no-log-prefix proxy 2>&1)"
  for name in "${ONE_TIME_NAMES[@]}"; do
    grep -qF -- "$name=***" <<<"$logs" || missing+=("$name")
  done
  echo "masked in the proxy's log: ${#ONE_TIME_NAMES[@]} names, missing: ${missing[*]:-none}"
  (( ${#missing[@]} == 0 ))
}
# A JWT: header and payload are base64url JSON, so both start with eyJ.
JWT_RE='eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}'
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" no_jwt_anywhere
no_jwt_anywhere() { # no access or ID token in any service's log, page evidence or test.log
  local logs in_logs files
  logs="$(compose logs --no-log-prefix 2>&1)"
  in_logs="$(grep -cE -- "$JWT_RE" <<<"$logs" || true)"
  # Page HTML saved by e2e.py (screenshots can't hold a copyable token), and this log so far.
  files="$(grep -lE -- "$JWT_RE" "$RESULTS"/*.html "$LOG" 2>/dev/null || true)"
  echo "log lines with a JWT: $in_logs; evidence files with a JWT: $(grep -c . <<<"$files" || true) of $(find "$RESULTS" -name '*.html' | wc -l) pages and test.log"
  [[ -n "$files" ]] && printf '  %s\n' "$files"
  (( in_logs == 0 )) && [[ -z "$files" ]]
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" api_challenge ...
api_challenge() { # <expected status> <WWW-Authenticate text> [curl args...]
  local want="$1" text="$2" out; shift 2
  out="$(curl -sS -i --cacert "$CERTS_DIR/ca.crt" --resolve "$LAB_HOST:$API_PORT:127.0.0.1" "$@" \
    "https://$LAB_HOST:$API_PORT/v1/whoami" | tr -d '\r')"
  grep -iE '^(HTTP/|www-authenticate:)' <<<"$out"
  head -n1 <<<"$out" | grep -q " $want " || { echo "expected HTTP $want"; return 1; }
  grep -iF -- "WWW-Authenticate: $text" <<<"$out" >/dev/null || { echo "expected WWW-Authenticate: $text"; return 1; }
}
# A PEM private key (the mTLS client's, or any other), header line only.
PEM_KEY_RE='-----BEGIN ([A-Z]+ )?PRIVATE KEY-----'
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" no_private_key_anywhere
no_private_key_anywhere() { # no PEM private key in any service's log or test.log
  local logs in_logs in_log
  logs="$(compose logs --no-log-prefix 2>&1)"
  in_logs="$(grep -cE -- "$PEM_KEY_RE" <<<"$logs" || true)"
  in_log="$(grep -cE -- "$PEM_KEY_RE" "$LOG" || true)"
  echo "log lines with a private key: $in_logs; test.log lines: $in_log"
  (( in_logs == 0 && in_log == 0 ))
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" mtls_status ...
mtls_status() { # <expected status> [with-cert|no-cert] -- the mutual-TLS route, from the host
  local want="$1" got
  if [[ "${2:-with-cert}" == no-cert ]]; then
    got="$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$CERTS_DIR/ca.crt" \
      --resolve "$LAB_HOST:$PROXY_MTLS_PORT:127.0.0.1" "https://$LAB_HOST:$PROXY_MTLS_PORT/")" || true
  else
    # shellcheck disable=SC2119  # no extra curl arguments here
    got="$(mtls_call)" || true
  fi
  echo "HTTP $got (${2:-with-cert})"
  [[ "$got" == "$want" ]]
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" api_preflight_ok
api_preflight_ok() { # the browser's preflight for a GET with a token, from the RP's origin
  local out
  out="$(curl -sS -D - -o /dev/null --cacert "$CERTS_DIR/ca.crt" --resolve "$LAB_HOST:$API_PORT:127.0.0.1" \
    -X OPTIONS -H "Origin: https://$LAB_HOST:$OIDC_RP_PORT" -H "Access-Control-Request-Method: GET" \
    -H "Access-Control-Request-Headers: authorization" "https://$LAB_HOST:$API_PORT/v1/whoami" | tr -d '\r')"
  grep -iE '^(HTTP/|access-control-)' <<<"$out"
  head -n1 <<<"$out" | grep -q ' 204 ' || { echo "expected HTTP 204"; return 1; }
  grep -qiF "Access-Control-Allow-Origin: https://$LAB_HOST:$OIDC_RP_PORT" <<<"$out" || { echo "expected the RP's origin"; return 1; }
  grep -qi '^Access-Control-Allow-Headers: Authorization$' <<<"$out" || { echo "expected Authorization allowed"; return 1; }
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
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" log_lacks ...
log_lacks()    { # <since> <service> <pattern> -- no line matches
  local logs n
  logs="$(compose logs --no-log-prefix --since "$1" "$2")"
  n="$(grep -cE -- "$3" <<<"$logs" || true)"
  echo "$(grep -c . <<<"$logs" || true) line(s) from $2 since $1; matching /$3/: $n"
  (( n == 0 ))
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" healthy ...
healthy()      {
  local st
  st="$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q "$1")")"
  [[ "$st" == healthy ]] || { echo "$1 health is $st"; return 1; }
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" restart_squid
restart_squid() { # restart the container, then wait for its health check
  compose restart squid && compose up -d --wait --wait-timeout 120 --no-deps squid
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" http_ok ...
http_ok()      { kc_curl -o /dev/null --resolve "$LAB_HOST:$2:127.0.0.1" "https://$LAB_HOST:$2$1"; }
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" issuer_ok ...
issuer_ok()    { # <port> [curl args...] -- discovery at that port reports it as the issuer
  local port="$1" iss; shift
  iss="$(kc_curl --resolve "$LAB_HOST:$port:127.0.0.1" "$@" \
    "https://$LAB_HOST:$port/realms/$REALM/.well-known/openid-configuration" | jq -r .issuer)"
  echo "issuer: $iss"
  [[ "$iss" == "https://$LAB_HOST:$port/realms/$REALM" ]] || { echo "expected https://$LAB_HOST:$port/realms/$REALM"; return 1; }
}

# --- Bring the lab up -----------------------------------------------------------
[[ -f "$ENV_FILE" ]] || "$LAB_ROOT/scripts/setup.sh"
load_env
load_secrets
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
for svc in postgres ldap keycloak saml-sp oidc-rp radius nas proxy saml-sp-proxied oidc-rp-proxied squid oidc-rp-egress oidc-rp-edge api; do
  check "health: $svc container healthy" healthy "$svc"
done
check "health: Keycloak issuer is https://$LAB_HOST:$KC_PORT/realms/$REALM" issuer_ok "$KC_PORT"
check "health: Keycloak issuer through the proxy is https://$LAB_HOST:$PROXY_KC_PORT/realms/$REALM" issuer_ok "$PROXY_KC_PORT"
# Sent straight to Keycloak, not from the proxy's address: must change nothing.
check "health: Keycloak ignores X-Forwarded-* except from the proxy" issuer_ok "$KC_PORT" \
  -H "X-Forwarded-Proto: http" -H "X-Forwarded-Host: attacker.example" -H "X-Forwarded-Port: 9999"
check "health: SAML SP /healthz over verified TLS" http_ok /healthz "$SAML_SP_PORT"
check "health: OIDC RP /healthz over verified TLS" http_ok /healthz "$OIDC_RP_PORT"
check "health: SAML SP /healthz through the proxy" http_ok /healthz "$PROXY_SAML_SP_PORT"
check "health: OIDC RP /healthz through the proxy" http_ok /healthz "$PROXY_OIDC_RP_PORT"
check "health: OIDC RP behind the egress proxy /healthz over verified TLS" http_ok /healthz "$EGRESS_OIDC_RP_PORT"
check "health: OIDC RP behind the egress proxy has no route to Keycloak without it" egress_no_direct_route
check "health: edge OIDC RP /healthz through the proxy (plain HTTP behind it)" http_ok /healthz "$PROXY_EDGE_RP_PORT"
check "health: API /healthz over verified TLS" http_ok /healthz "$API_PORT"
check "health: API without a token: 401, bare Bearer challenge" api_challenge 401 'Bearer realm="idlab-api"'
# Deliberately not a token: a fixed, made-up value.
check "health: API with a malformed token: 401 invalid_token" api_challenge 401 'Bearer realm="idlab-api", error="invalid_token"' \
  -H "Authorization: Bearer not-a-token"
check "health: API preflight from the OIDC RP's origin: 204, Authorization allowed" api_preflight_ok
check "health: mutual-TLS route accepts the partner client's certificate (curl)" mtls_status 200
check "health: mutual-TLS route refuses a request without a client certificate: 400" mtls_status 400 no-cert
check "health: LDAP bind as keycloak-svc (ldapwhoami over LDAPS)" ldap_bind_ok
check "health: authenticator app container healthy (RFC 6238 test vectors)" healthy authenticator
check "health: authenticator app has no network" authenticator_offline

# --- Baseline logins --------------------------------------------------------------
log "baseline logins"
check "login: SAML SP (alice)" browser saml --expect ok
check "login: OIDC RP (alice)" browser oidc --expect ok
check "login: SAML SP (dave, from LDAP)" browser_as dave saml --expect ok
check "login: OIDC RP (dave, from LDAP)" browser_as dave oidc --expect ok
check "login: SAML SP through the proxy (alice)" browser saml-proxy --expect ok
check "login: OIDC RP through the proxy (alice)" browser oidc-proxy --expect ok
check "login: SAML SP through the proxy (dave, from LDAP)" browser_as dave saml-proxy --expect ok
check "login: OIDC RP through the proxy (dave, from LDAP)" browser_as dave oidc-proxy --expect ok
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
check "login: OIDC RP through the egress proxy (alice)" browser oidc-egress --expect ok
check "login: OIDC RP through the egress proxy: back channel tunnelled by Squid" \
  log_has "$since" squid 'TCP_TUNNEL/200 [0-9]+ CONNECT keycloak:8180'
check "login: OIDC RP through the egress proxy (dave, from LDAP)" browser_as dave oidc-egress --expect ok
check "login: edge OIDC RP through the proxy, plain HTTP behind it (alice)" browser oidc-edge --expect ok
check "login: edge OIDC RP through the proxy, plain HTTP behind it (dave, from LDAP)" browser_as dave oidc-edge --expect ok
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
check "login: OIDC RP calls the API with its access token (alice)" browser oidc-api --expect ok
# iat and exp on the API's line: a log search computes the token's lifetime from them.
TS='[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z'
check "login: the API logs the token's iat and exp on each call" \
  log_has "$since" api "event=api_request_ok .* iat=$TS exp=$TS"
check "login: OIDC RP calls the API with its access token (dave, from LDAP)" browser_as dave oidc-api --expect ok
check "login: OIDC RP's debug page calls the API from the browser, cross-origin (alice)" browser oidc-cors --expect ok
check "login: OIDC RP hands out the raw access token on /debug/access-token (alice)" browser oidc-token --expect ok
check "login: mutual-TLS route accepts the partner client's certificate (browser)" browser mtls --expect ok
check "login: RADIUS Access-Accept (dave, from LDAP)" radius_login dave demo "nas: Access-Accept"
check "login: RADIUS Access-Reject (dave, wrong password)" radius_login dave wrong "nas: Access-Reject"

# --- MFA over RADIUS --------------------------------------------------------------------
# heidi is in the directory's mfa-required group: after her password the
# server answers Access-Challenge, and the NAS sends her code back with the State.
log "MFA over RADIUS"
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
check "radius mfa: heidi's password gets an Access-Challenge, with Message-Authenticator verified by the NAS" \
  radius_mfa new "nas: Access-Challenge (Message-Authenticator verified)" "nas: Access-Accept"
check "radius mfa: the server's log shows the challenge" log_has "$since" radius 'Auth: Challenge sent: \[heidi\]'
check "radius mfa: rlm_totp refuses the same code a second time: Access-Reject" radius_mfa again "nas: Access-Reject"
check "radius mfa: a wrong code: Access-Reject" radius_mfa wrong "nas: Access-Reject"
check "radius mfa: a State the server never issued is refused, even with a valid code" radius_forged_state
check "radius mfa: the NAS discards a challenge without Message-Authenticator, and never answers it" radius_tampered strip-ma
check "radius mfa: the NAS discards a challenge whose Message-Authenticator doesn't verify" radius_tampered bad-ma

# --- MFA logins -----------------------------------------------------------------------
# grace has a TOTP authenticator enrolled; Keycloak's browser flow asks her
# for a code after the password. Codes come from the authenticator app.
log "MFA logins"
check "mfa: OIDC RP (grace, password and one-time code)" mfa_login grace oidc new --expect ok
check "mfa: OIDC RP refuses a code grace has already used" mfa_login grace oidc again --expect-error "Invalid authenticator code."
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
check "mfa: OIDC RP refuses a wrong code (grace)" mfa_login grace oidc wrong --expect-error "Invalid authenticator code."
check "mfa: Keycloak logs the wrong code as LOGIN_ERROR invalid_user_credentials" \
  log_has "$since" keycloak 'type="LOGIN_ERROR".*error="invalid_user_credentials"'
check "mfa: Keycloak counted grace's 2 failed codes (brute-force protection)" bf_failures_are grace 2
# Start the later checks clean: two more failures would be nearer the lockout.
check "mfa: grace's failed logins cleared, as an admin's Unlock does" bf_clear_and_check grace
check "mfa: SAML SP (grace, password and one-time code)" mfa_login grace saml new --expect ok
# ivan is a new starter: Keycloak asks him to set up an authenticator at login.
check "mfa: a new starter (ivan) sets up an authenticator at first login" enrol_login ivan oidc --expect ok

# Break, check and fix one scenario. <name> [label prefixed to each check]
run_scenario() {
  local name="$1" label="${2:-}" user since ua_app ua_user
  load_scenario "$name"
  user="${SCENARIO_USER:-alice}"
  log "scenario: $label$name"
  check "$label$name: break"                   "$LAB_ROOT/scripts/break.sh" "$name"
  check "$label$name: detected as broken"      expect_state "$name" broken
  check "$label$name: break again is a no-op"  "$LAB_ROOT/scripts/break.sh" "$name"
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  check "$label$name: $user sees \"$SCENARIO_EXPECT\"" login_as "$user" "$SCENARIO_APP" --expect-error "$SCENARIO_EXPECT"
  if [[ -n "${SCENARIO_LOG:-}" ]]; then
    check "$label$name: log shows ${SCENARIO_LOG#* }" log_has "$since" "${SCENARIO_LOG%% *}" "${SCENARIO_LOG#* }"
  fi
  if [[ -n "${SCENARIO_LOG_ABSENT:-}" ]]; then
    check "$label$name: ${SCENARIO_LOG_ABSENT%% *} logs nothing matching ${SCENARIO_LOG_ABSENT#* }" \
      log_lacks "$since" "${SCENARIO_LOG_ABSENT%% *}" "${SCENARIO_LOG_ABSENT#* }"
  fi
  if [[ -n "${SCENARIO_UNAFFECTED:-}" ]]; then
    read -r ua_app ua_user <<<"$SCENARIO_UNAFFECTED"
    check "$label$name: $ua_user still logs in to $ua_app while broken" login_as "$ua_user" "$ua_app" --expect ok
  fi
  if [[ -n "${SCENARIO_ALSO:-}" ]]; then
    check "$label$name: $SCENARIO_ALSO" scenario_also_check
  fi
  check "$label$name: fix"                     "$LAB_ROOT/scripts/fix.sh" "$name"
  check "$label$name: detected as healthy"     expect_state "$name" healthy
  check "$label$name: fix again is a no-op"    "$LAB_ROOT/scripts/fix.sh" "$name"
  check "$label$name: login works again ($user)" login_as "$user" "$SCENARIO_APP" --expect ok
}

# --- Scenarios --------------------------------------------------------------------
for name in $(scenario_names); do
  run_scenario "$name"
done
# Fixing proxy-bypass recreates the RP, which drops the broken container's logs;
# fix.sh saves them first. Nothing else recreates the RP, so the newest save is the fix's.
check "proxy-bypass: fix saved the broken container's log, with backchannel_failed" \
  egress_saved_log_has 'event=oidc_login_failed reason=backchannel_failed'

# --- Restart ----------------------------------------------------------------------
# A stale /tmp/squid.pid once made Squid refuse to start after a restart
# ("Squid is already running"); /tmp is now a tmpfs, emptied on every start.
log "restart"
check "restart: squid container restarts and is healthy again" restart_squid
run_scenario proxy-auth-required "after squid restart: "

# --- Brute-force protection ----------------------------------------------------------
# It is on for the whole realm. No check before this one should have left a
# failed login on the existing users.
log "brute-force protection"
check "brute force: alice has no failed logins recorded" bf_failures_are alice 0
check "brute force: dave has no failed logins recorded" bf_failures_are dave 0

# --- Secrets ----------------------------------------------------------------------
log "secrets"
check "secrets: no value from .env, authorisation code, OAuth state or other one-time login value in any container's log" logs_free_of_secrets
check "secrets: the proxy's log has nonce, code_challenge, Signature, session_code and client_data, masked" proxy_masked_seen
check "secrets: no JWT in any container's log, saved page evidence or test.log" no_jwt_anywhere
check "secrets: no private key in any container's log or test.log" no_private_key_anywhere
check "secrets: leak scanners report a planted fake TOTP secret, one-time code and login-action URL" leak_scanners_selftest planted
check "secrets: leak scanners pass the same evidence without them (near misses only)" leak_scanners_selftest clean
check "secrets: no authorisation code, OAuth state or other one-time login value in test.log" testlog_free_of_login_values
check "secrets: no TOTP secret in any container's log, saved page or test.log" totp_secret_nowhere
check "secrets: no submitted one-time code in any container's log, saved page or test.log" codes_nowhere

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
