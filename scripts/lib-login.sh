# shellcheck shell=bash
# Logging in as a demo user, from scripts/test.sh and scripts/evidence-packs.sh.
# Source after lib.sh and load_env. The caller sets:
#   SEEN_DIR    a 0700 folder outside test-results/: e2e.py appends the cookie
#               values the browser held to $SEEN_DIR/cookie-values, for the leak checks
#   CODES_FILE  a 0600 file: the one-time codes submitted, one per line
# Nothing here prints a password, code or cookie value.

# tests_run [compose run options...] tests <e2e.py args> -- the browser, with
# the folder e2e.py appends the run's cookie values to.
# shellcheck disable=SC2329  # invoked by the browser helpers, themselves invoked indirectly
tests_run()    { compose run --rm -v "$SEEN_DIR:/seen" -e E2E_SEEN_FILE=/seen/cookie-values "$@"; }
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" browser ...
browser()      { tests_run tests "$@"; }
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" browser_as ...
browser_as()   { local user="$1"; shift; tests_run -e E2E_USER="$user" tests "$@"; }
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
  printf '%s\n' "$code" | tests_run -T -e E2E_USER="$user" -e E2E_OTP=stdin tests "$app" "$@"
}
# enrol_login <user> <app> --expect ok | --expect-error <text> -- a new
# starter's first login: the setup page, with an app that ignores the
# enrolment's algorithm and digits (e2e.py). The user is reset first.
# shellcheck disable=SC2329  # invoked indirectly: check "<name>" enrol_login ...
enrol_login() {
  local user="$1" app="$2"; shift 2
  new_starter_reset "$user" || return 1
  tests_run -T -e E2E_USER="$user" -e E2E_ENROL=1 tests "$app" "$@" </dev/null
}
