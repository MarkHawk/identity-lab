#!/usr/bin/env bash
# End-to-end test of the lab.
#
#   scripts/test.sh            build, start (or reuse) the lab, run all checks
#   scripts/test.sh --fresh    first remove the lab's containers AND its volumes
#                              (Keycloak database, directory, NAS secret) and the
#                              shared PC's saved browser state (.state/browser/), so
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
require docker curl jq openssl python3

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
# Cookie values the browser held during the run, one per line, appended by
# e2e.py (E2E_SEEN_FILE), for the leak checks. A 0700 folder outside
# test-results/, deleted on exit. Never printed.
SEEN_DIR="$(umask 077; mktemp -d)"
SEEN_FILE="$SEEN_DIR/cookie-values"
# Evidence newer than this was saved by this run.
RUN_MARK="$SEEN_DIR/run-start"
: >"$RUN_MARK"
# shellcheck disable=SC2329  # invoked by the EXIT trap
on_exit() { redact_log; rm -f "$CODES_FILE"; rm -rf "$SEEN_DIR"; }
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
# The login helpers (login_as and the rest) are shared with evidence-packs.sh.
# shellcheck source=lib-login.sh
source "$LAB_ROOT/scripts/lib-login.sh"
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
# radius_replay_concurrent -- a one-time code really is one-time, even when
# the same code is offered again while other RADIUS requests run alongside.
# Spend a fresh code, then replay it many times under concurrent load; every
# replay must be refused. Driven inside the NAS with radclient; the password
# and code arrive on stdin, never on a command line, so they aren't logged.
# The regression test for rlm_totp in FreeRADIUS 3.2.4 to 3.2.10, which could
# accept a spent code again; fixed upstream on the v3.2.x branch in commit
# 3e3f261, not yet in a release (v4 isn't affected). It passes because the
# lab records spent codes itself (radius/mods/cache), whatever rlm_totp does.
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" radius_replay_concurrent
radius_replay_concurrent() {
  local code out acc valid
  code="$(totp_for heidi new)" || { echo "$code"; return 1; }
  # The script runs in the nas container. It reads the password then the code
  # from stdin, gets a challenge State (round 1), and sends the code back
  # (round 2). It spends the code once, then replays it 30 times, each replay
  # fired next to a few concurrent LDAP logins (dave) to churn the server's
  # request memory. It prints only a count, never a code.
  # shellcheck disable=SC2016  # $PW/$CODE expand in the nas container, not here
  local script='
set -u
IFS= read -r PW; IFS= read -r CODE
S=/var/lib/nas/secret; SRV=radius:1812
r1() { printf "User-Name = \"heidi\"\nUser-Password = \"%s\"\nNAS-Identifier = \"nas\"\nMessage-Authenticator = 0x00\n" "$PW" \
  | radclient -x -r 3 -t 2 -S "$S" "$SRV" auth 2>/dev/null | sed -n "s/^\tState = //p" | head -1; }
r2() { printf "User-Name = \"heidi\"\nUser-Password = \"%s\"\nState = %s\nNAS-Identifier = \"nas\"\nMessage-Authenticator = 0x00\n" "$CODE" "$1" \
  | radclient -r 1 -t 2 -S "$S" "$SRV" auth 2>/dev/null | grep -oE "Access-(Accept|Reject)" | head -1; }
dave() { printf "User-Name = \"dave\"\nUser-Password = \"%s\"\nNAS-Identifier = \"nas\"\nMessage-Authenticator = 0x00\n" "$PW" \
  | radclient -r 1 -t 2 -S "$S" "$SRV" auth >/dev/null 2>&1; }
state() { local s n=0; while [ $n -lt 4 ]; do s=$(r1); [ -n "$s" ] && { printf "%s" "$s"; return; }; n=$((n + 1)); done; }
spent=0
for t in 1 2 3 4 5; do s=$(state); [ -n "$s" ] || continue; r=$(r2 "$s")
  [ "$r" = Access-Accept ] && { spent=1; break; }; [ "$r" = Access-Reject ] && break; done
[ "$spent" = 1 ] || { echo "spend-failed"; exit 0; }
acc=0; valid=0
for i in $(seq 1 30); do
  res=""
  for t in 1 2 3; do
    s=$(state); [ -n "$s" ] || continue
    for c in 1 2 3; do dave & done
    res=$(r2 "$s"); wait
    [ -n "$res" ] && break
  done
  [ -n "$res" ] || continue
  valid=$((valid + 1))
  [ "$res" = Access-Accept ] && acc=$((acc + 1))
done
echo "accepted:$acc valid:$valid"
'
  out="$(printf '%s\n%s\n' "$DEMO_PASSWORD" "$code" | compose exec -T nas bash -c "$script" 2>&1)" || true
  echo "$out"
  grep -q 'spend-failed' <<<"$out" && { echo "could not spend a code to replay"; return 1; }
  acc="$(sed -n 's/.*accepted:\([0-9]*\).*/\1/p' <<<"$out")"
  valid="$(sed -n 's/.*valid:\([0-9]*\).*/\1/p' <<<"$out")"
  [ "${valid:-0}" -ge 20 ] || { echo "inconclusive: only ${valid:-0} replays got a reply"; return 1; }
  [ "${acc:-1}" -eq 0 ] || { echo "a spent code was accepted again: $acc of $valid replays"; return 1; }
  echo "all $valid replays refused"
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

# --- Browser evidence ------------------------------------------------------------
# e2e.py saves a redacted HAR, a cookie summary and the console with every run
# (tests/evidence.py). These check that none of them holds a secret, with the
# same patterns as the logs and pages, plus what only a HAR can leak: cookie
# values, Authorization values, form fields, response bodies, SAML messages.
# Base64 of "<samlp:" and "<saml:": the start of a SAML message, unmasked.
SAML_B64_RE='PHNhbWxwO|PHNhbWw6'
SAML_PARAM_RE='(SAMLRequest|SAMLResponse|RelayState)=[^*&[:space:]"]'
# jq: the number of places in a HAR where a value survived redaction.
# shellcheck disable=SC2016  # jq, not shell
HAR_UNREDACTED_JQ='[.log.entries[] |
  (.request.cookies[]?, .response.cookies[]? | select(.value != "<redacted>")),
  (.request.headers[]?, .response.headers[]? | select(.name | ascii_downcase | . == "cookie" or . == "set-cookie")
     | .value | split("\n")[] | split(";")[] | ltrimstr(" ") | select(test("^[^=]+=") and (test("^[^=]+=<redacted>$") | not))
     | select(test("^(Path|Domain|Expires|Max-Age|SameSite|Priority|Partitioned|Version|Comment)="; "i") | not)),
  (.request.headers[]? | select(.name | ascii_downcase | . == "authorization" or . == "proxy-authorization")
     | select(.value | endswith("<redacted>") | not)),
  (.request.postData.params[]? | select((.name | ascii_downcase | IN("username", "login", "credentialid", "rememberme") | not) and .value != "***")),
  (.response.content | select(has("text")))
] | length'

# scan_browser_evidence <seen-values-file> <test.log> [file...] -- 0 when no
# saved HAR, cookie summary or console log holds a secret. Prints counts and
# file names, never a value.
# shellcheck disable=SC2329  # invoked by the checks below
scan_browser_evidence() {
  local seen="$1" log="$2" f v n=0 bad=0 values=0 hars=0 sums=0 out; shift 2
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    n=$((n + 1)) out=""
    for v in "${SECRETS[@]}"; do grep -qF -- "$v" "$f" && out+="a secret from .env; " && break; done
    grep -qE -- "$JWT_RE" "$f" && out+="a JWT; "
    grep -qE -- "$AUTH_CODE_RE" "$f" && out+="an authorisation code; "
    grep -qE -- "$STATE_RE" "$f" && out+="an OAuth state value; "
    grep -qE -- "$ONE_TIME_RE" "$f" && out+="an unmasked ${ONE_TIME_NAMES[*]}; "
    grep -qE -- "$SAML_PARAM_RE|$SAML_B64_RE" "$f" && out+="a SAML message or RelayState; "
    if [[ -s "$seen" ]] && grep -qFf "$seen" "$f"; then out+="a cookie value the browser held; "; fi
    case "$f" in
      *.har)
        hars=$((hars + 1))
        v="$(jq -r "$HAR_UNREDACTED_JQ" "$f" 2>/dev/null || echo unreadable)"
        [[ "$v" == 0 ]] || out+="unredacted HAR fields: $v; " ;;
      *-cookies.json)
        sums=$((sums + 1))
        jq -e '[paths | .[-1] | select(. == "value")] | length == 0' "$f" >/dev/null || out+="a cookie value field; "
        jq -e '.selfCheck.filesWithAValue == 0' "$f" >/dev/null || out+="no clean self-check from e2e.py; " ;;
    esac
    if [[ -n "$out" ]]; then bad=$((bad + 1)); echo "  ${f##*/}: ${out%; }"; fi
  done
  [[ -s "$seen" ]] && values="$(sort -u "$seen" | grep -c .)"
  if [[ -s "$seen" ]] && grep -qFf "$seen" "$log"; then bad=$((bad + 1)); echo "  ${log##*/}: a cookie value the browser held"; fi
  echo "checked $n browser evidence file(s) ($hars HAR, $sums cookie summaries) and ${log##*/} against $values cookie value(s): $bad with a secret"
  (( bad == 0 ))
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" browser_evidence_clean
browser_evidence_clean() {
  local files=()
  mapfile -t files < <(find "$RESULTS" -maxdepth 1 \( -name '*.har' -o -name '*-cookies.json' -o -name '*-console.txt' \) | sort)
  (( ${#files[@]} > 0 )) || { echo "no browser evidence in $RESULTS"; return 1; }
  scan_browser_evidence "$SEEN_FILE" "$LOG" "${files[@]}"
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" browser_evidence_complete
browser_evidence_complete() { # every browser run of this test.sh saved all three files
  # A run is its <app>-<time> stamp, from any file it saved: a browser error
  # page (ERR_TOO_MANY_REDIRECTS) can't be screenshotted, so not every run has a .png.
  local s n=0 missing=()
  while read -r s; do
    [[ -n "$s" ]] || continue
    n=$((n + 1))
    [[ -f "$RESULTS/$s.har" && -f "$RESULTS/$s-cookies.json" && -f "$RESULTS/$s-console.txt" ]] || missing+=("$s")
  done < <(find "$RESULTS" -maxdepth 1 -newer "$RUN_MARK" -regextype posix-extended \
             -regex '.*/[a-z-]+-[0-9]+(\.png|\.html|\.har|-cookies\.json|-console\.txt)' -printf '%f\n' \
           | sed -E 's/(\.png|\.html|\.har|-cookies\.json|-console\.txt)$//' | sort -u)
  echo "this run: $n browser run(s), $(find "$RESULTS" -maxdepth 1 -name '*.png' -newer "$RUN_MARK" | wc -l) with a screenshot;" \
    "missing a HAR, cookie summary or console log: ${#missing[@]}"
  (( ${#missing[@]} == 0 )) || printf '  %s\n' "${missing[@]}"
  (( n > 0 && ${#missing[@]} == 0 ))
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" cookie_values_not_in_logs
cookie_values_not_in_logs() { # no cookie value the browser held in any container's log
  local logs n
  [[ -s "$SEEN_FILE" ]] || { echo "e2e.py recorded no cookie values, so nothing to check"; return 1; }
  logs="$(compose logs --no-log-prefix 2>&1)"
  n="$(grep -cFf "$SEEN_FILE" <<<"$logs" || true)"
  echo "checked $(sort -u "$SEEN_FILE" | grep -c .) cookie value(s) against $(wc -l <<<"$logs") log lines: $n line(s) with one"
  (( n == 0 ))
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" kc_login_events_clean
kc_login_events_clean() { # Keycloak's successful LOGIN lines: there are some, and they hold no secret
  # (one-time codes in them are covered by codes_nowhere, over every log)
  local lines v n=0 bad=""
  lines="$(compose logs --no-log-prefix keycloak 2>&1 | grep -F 'type="LOGIN"' || true)"
  n="$(grep -c . <<<"$lines" || true)"
  (( n > 0 )) || { echo "Keycloak logged no successful LOGIN event"; return 1; }
  for v in "${SECRETS[@]}"; do grep -qF -- "$v" <<<"$lines" && { bad+="a secret from .env; "; break; }; done
  grep -qE -- "$JWT_RE" <<<"$lines" && bad+="a JWT; "
  grep -qE -- "$AUTH_CODE_RE" <<<"$lines" && bad+="an authorisation code; "
  grep -qE -- "$STATE_RE|$ONE_TIME_RE" <<<"$lines" && bad+="a state or one-time login value; "
  if [[ -s "$SEEN_FILE" ]] && grep -qFf "$SEEN_FILE" <<<"$lines"; then bad+="a cookie value; "; fi
  # Field names only, from the first line: what a LOGIN event carries.
  echo "$n successful LOGIN line(s) in Keycloak's log; fields: $(head -n1 <<<"$lines" | grep -oE '[a-zA-Z_]+="' | tr -d '="' | paste -sd' ')"
  [[ -z "$bad" ]] || { echo "  found: ${bad%; }"; return 1; }
}

# The browser evidence scanner's self-test: a made-up HAR and cookie summary
# as e2e.py writes them, and (planted) the same with values left in. Nothing
# from .env or the lab; the values are assembled here so that no file holds them.
# shellcheck disable=SC2329  # invoked by browser_evidence_selftest
evidence_selftest_dir() { # <dir> <clean|planted>
  local d="$1" cv="sel""ftest-cookie-$RANDOM$RANDOM" sv sb
  printf '%s\n' "$cv" >"$d/seen"
  sv="$(printf 'not a real SAML response' | base64 -w0)"
  sb="$(printf '<samlp:Response ID="selftest"/>' | base64 -w0)"
  if [[ "$2" == clean ]]; then
    cat >"$d/run.har" <<HAR
{"log": {"entries": [{"request": {"method": "POST", "url": "https://idlab.example:8181/saml/acs?code=***&state=***",
  "headers": [{"name": "Cookie", "value": "saml_sp_session=<redacted>"}, {"name": "Authorization", "value": "Bearer <redacted>"}],
  "cookies": [{"name": "saml_sp_session", "value": "<redacted>"}],
  "postData": {"mimeType": "application/x-www-form-urlencoded", "text": "SAMLResponse=***&RelayState=***&username=alice",
    "params": [{"name": "SAMLResponse", "value": "***"}, {"name": "username", "value": "alice"}]}},
 "response": {"status": 302, "headers": [{"name": "Set-Cookie", "value": "saml_sp_session=<redacted>; HttpOnly; Path=/; SameSite=None"}],
  "cookies": [{"name": "saml_sp_session", "value": "<redacted>"}], "content": {"size": 0}}}]}}
HAR
    printf '{"steps": [{"cookies": [{"name": "saml_sp_session", "secure": false}]}], "selfCheck": {"filesWithAValue": 0}}\n' >"$d/run-cookies.json"
  else
    cat >"$d/run.har" <<HAR
{"log": {"entries": [{"request": {"method": "POST", "url": "https://idlab.example:8181/saml/acs",
  "headers": [{"name": "Cookie", "value": "saml_sp_session=$cv"}, {"name": "Authorization", "value": "Bearer abc"}],
  "cookies": [{"name": "saml_sp_session", "value": "$cv"}],
  "postData": {"mimeType": "application/x-www-form-urlencoded", "text": "SAMLResponse=$sb&password=x",
    "params": [{"name": "SAMLResponse", "value": "$sv"}, {"name": "password", "value": "x"}]}},
 "response": {"status": 200, "headers": [{"name": "Set-Cookie", "value": "saml_sp_session=$cv; HttpOnly; Path=/"}],
  "cookies": [], "content": {"size": 9, "text": "selftest"}}}]}}
HAR
    printf '{"steps": [{"cookies": [{"name": "saml_sp_session", "value": "%s"}]}]}\n' "$cv" >"$d/run-cookies.json"
  fi
  printf 'info: nothing here\n' >"$d/run-console.txt"
  printf '=== selftest\n' >"$d/test.log"
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" browser_evidence_selftest ...
browser_evidence_selftest() { # <clean|planted> -- clean passes; planted is reported in both files
  local d out rc=0
  d="$(mktemp -d)"
  evidence_selftest_dir "$d" "$1"
  out="$(scan_browser_evidence "$d/seen" "$d/test.log" "$d/run.har" "$d/run-cookies.json" "$d/run-console.txt")" || rc=$?
  rm -rf "$d"
  printf 'scanner (exit %d):\n%s\n' "$rc" "$out"
  if [[ "$1" == clean ]]; then
    (( rc == 0 ))
  else
    (( rc != 0 )) \
      && grep -qE 'run\.har: .*a SAML message.*a cookie value the browser held; unredacted HAR fields: [1-9]' <<<"$out" \
      && grep -qE 'run-cookies\.json: a cookie value the browser held; a cookie value field; no clean self-check' <<<"$out"
  fi
}

# --- Evidence packs ------------------------------------------------------------
# evidence-packs/ (scripts/evidence-packs.sh) is committed, so the checks
# below read what's in the repository: no pack or answer key may hold a
# secret or a real address or name, no pack may give its answer away, and
# normalising time must keep every clock offset and expiry true.
PACKS_DIR="$LAB_ROOT/evidence-packs"
PRIVATE_IP_RE='(^|[^0-9.])(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}([^0-9.]|$)'
# scan_packs <file>... -- 0 when none holds a secret, a token, a one-time value,
# a SAML message, a key, LAB_HOST, a private address, a home folder or the
# host user's or host's name (whole words only: "bookmark" is not "mark").
# Prints file names and what was found, never a value.
# shellcheck disable=SC2329  # invoked by the checks below
scan_packs() {
  local f v out bad=0 n=0 me host
  me="$(id -un)" host="$(hostname)"
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    n=$((n + 1)) out=""
    for v in "${SECRETS[@]}" "${TOTP_SECRETS[@]}"; do grep -qF -- "$v" "$f" && { out+="a secret from .env; "; break; }; done
    grep -qE -- "$JWT_RE" "$f" && out+="a JWT; "
    grep -qE -- "$AUTH_CODE_RE" "$f" && out+="an authorisation code; "
    grep -qE -- "$STATE_RE|$ONE_TIME_RE" "$f" && out+="a state or one-time login value; "
    grep -qE -- "$SAML_PARAM_RE|$SAML_B64_RE" "$f" && out+="a SAML message; "
    grep -qE -- "$PEM_KEY_RE|-----BEGIN CERTIFICATE-----" "$f" && out+="a PEM block; "
    if [[ "$LAB_HOST" != localhost ]] && grep -qiwF -- "$LAB_HOST" "$f"; then out+="LAB_HOST; "; fi
    grep -qE -- "$PRIVATE_IP_RE" "$f" && out+="a private IP address; "
    grep -oE -- "/home/[A-Za-z0-9_.-]+" "$f" | grep -qvx /home/user && out+="a home folder; "
    { grep -qF -- "/home/$me" "$f" || grep -qF -- "$me@" "$f" || grep -qw -- "$me" "$f"; } && out+="the host user's name; "
    grep -qw -- "$host" "$f" && out+="the host's name; "
    if [[ -n "$out" ]]; then bad=$((bad + 1)); echo "  ${f##*/}: ${out%; }"; fi
  done
  echo "checked $n pack and answer file(s): $bad with something that must not be there"
  (( n > 0 && bad == 0 ))
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" evidence_packs_clean
evidence_packs_clean() { scan_packs "$PACKS_DIR"/packs/*.json "$PACKS_DIR"/answers/*.json; }
# The scanner's self-test: a made-up pack, clean, then with a planted fake JWT,
# a private address and a home folder. Nothing from .env.
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" evidence_packs_selftest ...
evidence_packs_selftest() { # <clean|planted>
  local d out rc=0
  d="$(mktemp -d)"
  if [[ "$1" == clean ]]; then
    printf '{"tools": [{"lines": [{"text": "bookmark at https://lab.example:8180/ from 192.0.2.10, /home/user, state=***"}]}]}\n' >"$d/case-000000.json"
  else
    printf '{"tools": [{"lines": [{"text": "eyJmYWtlLWhlYWRlci0xMjM.eyJmYWtlLXBheWxvYWQtMTIz.sig from 10.20.30.40 in /home/someone"}]}]}\n' >"$d/case-000000.json"
  fi
  out="$(scan_packs "$d"/*.json)" || rc=$?
  rm -rf "$d"
  echo "$out"
  if [[ "$1" == clean ]]; then (( rc == 0 ))
  else (( rc != 0 )) && grep -q 'a JWT; a private IP address; a home folder' <<<"$out"; fi
}
# evidence_packs_hide_answers -- no pack names a scenario, a runbook, the fix
# or a scenario's summary. (The answer keys hold those, and are read apart.)
# evidence_packs_no_probes -- no pack holds the lab's own state-detection
# traffic: status.sh's and the scenarios' HTTP probes carry the user agent
# idlab-status, or curl's. (The builder never runs detection inside a pack's
# window, so its probes without a user agent, such as an LDAP connection test,
# can't be there either; this checks the ones that can be recognised.)
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" evidence_packs_no_probes
evidence_packs_no_probes() {
  local f n=0 hits=0
  for f in "$PACKS_DIR"/packs/*.json; do
    n=$((n + 1))
    if grep -qE -- 'idlab-status|curl/[0-9]' "$f"; then hits=$((hits + 1)); echo "  ${f##*/}: $(grep -cE -- 'idlab-status|curl/[0-9]' "$f") probe line(s)"; fi
  done
  echo "checked $n pack(s): $hits with state-detection probe traffic"
  (( n > 0 && hits == 0 ))
}
# evidence_packs_no_headless -- no pack shows the Playwright browser's user
# agent (HeadlessChrome); the builder replaces it with an ordinary Chrome's.
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" evidence_packs_no_headless
evidence_packs_no_headless() {
  local f n=0 hits=0
  for f in "$PACKS_DIR"/packs/*.json; do
    n=$((n + 1))
    if grep -qi -- 'HeadlessChrome' "$f"; then hits=$((hits + 1)); echo "  ${f##*/}: $(grep -ci -- 'HeadlessChrome' "$f") line(s)"; fi
  done
  echo "checked $n pack(s): $hits mention HeadlessChrome"
  (( n > 0 && hits == 0 ))
}
# evidence_packs_nginx_levels -- every nginx error-log line in a pack is rated by
# its level: [error], [crit], [alert], [emerg] error; [warn] warning.
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" evidence_packs_nginx_levels
evidence_packs_nginx_levels() {
  local n
  n="$(jq -rs '[.[] | .tools[] | .lines[] | select(.text | test("[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]{8} \\[(error|crit|alert|emerg|warn)\\] "))
      | select((.text | test("\\[warn\\]")) as $w | (if $w then .severity != "warning" else .severity != "error" end))] | length' "$PACKS_DIR"/packs/*.json)"
  echo "$n nginx error-log line(s) with the wrong severity"
  (( n == 0 ))
}
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" evidence_packs_hide_answers
evidence_packs_hide_answers() {
  local f name hits=0 found
  for f in "$PACKS_DIR"/packs/*.json; do
    found=""
    for name in $(scenario_names); do
      load_scenario "$name"
      grep -qF -- "$name" "$f" && found+="the name $name; "
      grep -qF -- "$SCENARIO_SUMMARY" "$f" && found+="the summary of $name; "
    done
    grep -qiE -- 'runbook|scenario|break\.sh|fix\.sh' "$f" && found+="runbook, scenario, break.sh or fix.sh; "
    if [[ -n "$found" ]]; then hits=$((hits + 1)); echo "  ${f##*/}: ${found%; }"; fi
  done
  echo "checked $(find "$PACKS_DIR/packs" -name '*.json' | wc -l) pack(s): $hits give their answer away"
  (( hits == 0 ))
}

# --- Bring the lab up -----------------------------------------------------------
[[ -f "$ENV_FILE" ]] || "$LAB_ROOT/scripts/setup.sh"
load_env
load_secrets
log "LAB_HOST=$LAB_HOST"

if (( FRESH )); then
  log "--fresh: removing lab containers and the Keycloak database volume"
  compose --profile test down -v --remove-orphans
  # Keycloak's sessions went with its database: so does the shared PC's saved copy of one.
  rm -f "$STATE_DIR/browser/"* 2>/dev/null || true
fi
# The tests container mounts it; if Docker had to create it, it would be root's.
mkdir -p "$STATE_DIR/browser"; chmod 700 "$STATE_DIR/browser"

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
check "radius mfa: a one-time code can't be replayed under concurrent load" radius_replay_concurrent
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
check "secrets: the browser evidence redactor removes made-up cookie values, tokens, codes, SAML messages, passwords and one-time codes" \
  compose run --rm -T --entrypoint python3 tests /tests/evidence.py selftest
check "secrets: browser evidence scanner reports a planted cookie value, SAML message and unredacted HAR fields" browser_evidence_selftest planted
check "secrets: browser evidence scanner passes the same evidence redacted" browser_evidence_selftest clean
check "secrets: every browser run saved a HAR, a cookie summary and its console" browser_evidence_complete
check "secrets: no secret, token, code, SAML message or cookie value in any saved HAR, cookie summary or console log" browser_evidence_clean
check "secrets: no cookie value the browser held in any container's log" cookie_values_not_in_logs
check "secrets: Keycloak's successful LOGIN events hold no secret, token, code or cookie value" kc_login_events_clean

# --- Evidence packs ----------------------------------------------------------------
log "evidence packs"
check "packs: scanner reports a planted fake JWT, private address and home folder" evidence_packs_selftest planted
check "packs: scanner passes a made-up clean pack (bookmark, placeholders, masked state)" evidence_packs_selftest clean
check "packs: no secret, token, one-time value, SAML message, key, real address or name in any pack or answer key" evidence_packs_clean
check "packs: no pack names its scenario, runbook, fix or summary" evidence_packs_hide_answers
check "packs: no pack holds the lab's state-detection probe traffic (idlab-status or curl user agents)" evidence_packs_no_probes
check "packs: no pack shows the browser's HeadlessChrome user agent" evidence_packs_no_headless
check "packs: nginx error-log lines are rated by their level ([error] error, [warn] warning)" evidence_packs_nginx_levels
check "packs: every pack has the format, every tool and valid severities, and an answer key" \
  python3 -I "$LAB_ROOT/tests/packs.py" validate "$PACKS_DIR/packs" "$PACKS_DIR/answers"
check "packs: the time normaliser shifts every format the lab prints by the same delta (self-test)" \
  python3 -I "$LAB_ROOT/tests/packs.py" selftest
check "packs: clock offsets and certificate expiry survive time normalisation (clock-skew, totp-clock-drift, expired-signing-cert, client-cert-*, healthy)" \
  python3 -I "$LAB_ROOT/tests/packs.py" check-time "$PACKS_DIR/packs" "$PACKS_DIR/answers"

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
