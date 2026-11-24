# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The realm's login timeout (Keycloak's "Login timeout": how long a user has
# from opening the login page to submitting it) is cut from 30 minutes to 20
# seconds. Someone who opens the login page, answers the phone and comes back
# submits a form whose login session Keycloak has already thrown away. The
# browser still holds the session cookie, so Keycloak recognises it, but the
# server side is gone: it shows the login form again with "Your login attempt
# timed out. Login will start from the beginning." and logs LOGIN_ERROR with
# error="expired_code". Typing the password again straight away works.
#
# The Admin API accepts any value from 1 second (0 and negative are refused,
# "cannot be 0"); the admin console may impose a larger minimum, which wasn't
# tried. 20 s is long enough for the lab's own scripted logins and short
# enough to wait out (tests/e2e.py waits 30 s: STALE_WAIT_SECONDS).
SCENARIO_SUMMARY="the realm's login timeout is 20 seconds: a login page left open that long expires"
SCENARIO_RUNBOOK="runbooks/25-login-timeout.md"
SCENARIO_APP=oidc-stale
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="Your login attempt timed out. Login will start from the beginning."
SCENARIO_SEEN_AT="on Keycloak's login form, after the user signs in on a page that has been open for more than 20 seconds"
SCENARIO_LOG='keycloak type="LOGIN_ERROR".*clientId="oidc-rp".*error="expired_code"'
SCENARIO_ALSO="the HAR shows the form POST sent more than the timeout after the login page, still with its session cookie; a saved login URL opened with no cookies gets \"cookie not found\", logged as cookie_not_found; and an admin event records the realm update"

_lt_healthy=1800
_lt_broken=20

_lt_live() { kc_api GET "/$REALM" | jq -r .accessCodeLifespanLogin; }

scenario_detect() {
  local live
  live="$(_lt_live 2>/dev/null)" || { printf 'unknown\tKeycloak admin API unreachable\n'; return; }
  if [[ "$live" == "$_lt_healthy" ]]; then
    printf 'healthy\trealm login timeout (accessCodeLifespanLogin): %s s\n' "$live"
  else
    printf 'broken\trealm login timeout (accessCodeLifespanLogin): %s s, healthy is %s s\n' "$live" "$_lt_healthy"
  fi
}

# As the admin console's Sessions settings tab saves it: the whole realm,
# with the one value changed.
_lt_set() {
  local rep
  rep="$(kc_api GET "/$REALM")" || die "Keycloak admin API unreachable"
  kc_api PUT "/$REALM" "$(jq -c --argjson v "$1" '.accessCodeLifespanLogin = $v' <<<"$rep")" >/dev/null
}
scenario_break() { _lt_set "$_lt_broken"; }
scenario_fix()   { _lt_set "$_lt_healthy"; }

# shellcheck disable=SC2329  # invoked by scripts/test.sh while broken
scenario_also_check() {
  local har jar out events secs
  har="$(find "$LAB_ROOT/test-results" -maxdepth 1 -name 'oidc-stale-[0-9]*.har' -printf '%T@ %p\n' | sort -n | tail -n 1 | cut -d' ' -f2-)"
  [[ -n "$har" ]] || { echo "no oidc-stale-*.har in test-results/"; return 1; }
  jar="${har%.har}-cookies.json"
  echo "evidence: ${har##*/}, ${jar##*/}"
  # 1. The HAR: the form POST came well after the login page, with its session cookie.
  secs="$(jq -er '
      def secs: sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;
      ([.log.entries[] | select(.request.method == "GET" and (.request.url | test("/protocol/openid-connect/auth\\?")))][0].startedDateTime | secs) as $page
      | [.log.entries[] | select(.request.method == "POST" and (.request.url | test("/login-actions/authenticate")))][0]
      | select(.request.cookies | map(.name) | index("AUTH_SESSION_ID"))
      | select(.response.status == 302 and (.response.redirectURL | test("/login-actions/authenticate")))
      | (.startedDateTime | secs) - $page | select(. > 20)' "$har")" \
    || { echo "the HAR has no login form POST, with an AUTH_SESSION_ID cookie and a redirect back to the login form, more than 20 s after the login page"; return 1; }
  echo "the form POST went $secs s after the login page, with an AUTH_SESSION_ID cookie, and Keycloak redirected to the login form again, not to the app"
  jq -e '[.log.entries[] | select(.request.method == "GET" and .response.status == 200 and (.request.url | test("/login-actions/authenticate")))] | length > 0' "$har" >/dev/null \
    || { echo "the HAR shows no login form served again after the POST"; return 1; }
  jq -e '[.log.entries[] | select(.request.url | test("/auth/callback"))] | length == 0' "$har" >/dev/null \
    || { echo "the HAR shows a redirect to the app's callback: the login did not time out"; return 1; }
  # 2. The cookie jar: Keycloak's login-session cookie, but no SSO session was made.
  jq -er '.steps[] | select(.step == "end") | [.cookies[].name] | select(index("AUTH_SESSION_ID") != null and index("KEYCLOAK_IDENTITY") == null)
      | "at the end the jar has: " + join(" ") + " (no KEYCLOAK_IDENTITY: nobody signed in)"' "$jar" \
    || { echo "the cookie summary should hold AUTH_SESSION_ID but not KEYCLOAK_IDENTITY at the end"; return 1; }
  # 3. The bookmark variant: a saved login URL, opened with no cookies.
  out="$(login_as alice oidc-bookmark --expect-error "Restart login cookie not found." 2>&1)" \
    || { echo "$out"; return 1; }
  grep -F '[oidc-bookmark]' <<<"$out" | sed -E 's/(state|code|session_code|client_data|tab_id)=[^& ]+/\1=.../g'
  log_has "$(date -u -d '-3 minutes' +%Y-%m-%dT%H:%M:%SZ)" keycloak 'type="LOGIN_ERROR".*error="cookie_not_found"' \
    || { echo "no cookie_not_found event in Keycloak's log"; return 1; }
  # 4. Who changed it, and when: the realm's admin events (no details are kept).
  events="$(kc_api GET "/$REALM/admin-events?operationTypes=UPDATE&resourceTypes=REALM&max=5")" || return 1
  jq -r '.[] | "admin event: \(.operationType) \(.resourceType) at \(.time / 1000 | todate) from \(.authDetails.ipAddress)"' <<<"$events"
  (( $(jq --argjson since "$(( ($(date +%s) - 300) * 1000 ))" '[.[] | select(.time >= $since)] | length' <<<"$events") > 0 ))
}
