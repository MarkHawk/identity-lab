# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# carol signed in to Keycloak at a shared computer, signed out of the app (its
# "Clear local session" button) and walked away. That only ends the app's own
# session: Keycloak's session cookies stay in the browser. The next person,
# alice, opens the app, clicks Log in, and Keycloak recognises the browser, so
# it sends her straight back to the app signed in as carol, with no login form
# and no password. Nothing is wrong on any server: every request succeeds, and
# Keycloak logs a good login for carol. The app shows carol's name and carol's
# (missing) roles, and alice thinks the app has "lost her access".
#
# The fault lives in the browser, which the lab can't reach, so the lab keeps a
# stand-in for the shared PC: its saved browser state, .state/browser/shared-pc.json
# (Keycloak's cookies only; the cookie values make it private to this user, mode
# 0600, gitignored). break signs carol in with the test browser and leaves that
# session open. The next login at that PC (oidc-shared-pc) loads it. A login in
# a fresh browser (any other computer) is unaffected, as it would be in life.
# fix signs carol out of Keycloak in that browser, by Keycloak's own logout page,
# and deletes the state file, so no cookie value stays on disk.
SCENARIO_SUMMARY="carol left a Keycloak session open at a shared PC: alice's login there signs her in as carol"
SCENARIO_RUNBOOK="runbooks/26-wrong-account.md"
SCENARIO_APP=oidc-shared-pc
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="Signed in as carol@idlab.example, not alice@idlab.example"
SCENARIO_SEEN_AT="on the app's page straight after Log in, with no login form: the identity shown is carol's, not alice's"
SCENARIO_LOG='oidc-rp event=oidc_login_ok sub=\S+ preferred_username=carol email=carol@idlab.example'
SCENARIO_ALSO="the browser evidence shows no login form and the app showing carol, without the lab-user role alice has; Keycloak logged a LOGIN for carol, and her one session was left open from before"

_wa_user=carol
_wa_state="$STATE_DIR/browser/shared-pc.json"

# The sub and sid inside the saved KEYCLOAK_IDENTITY cookie, as one JSON object
# (they name the user and the session; they aren't secrets and the cookie value
# itself is never printed: it goes through pipes only). Empty if there is none.
_wa_cookie_claims() {
  local p
  p="$(jq -r '[.cookies[]? | select(.name == "KEYCLOAK_IDENTITY") | .value][0] // empty' "$_wa_state" 2>/dev/null | cut -d. -f2 | tr '_-' '/+')"
  [[ -n "$p" ]] || return 0
  printf '%s%s' "$p" "$(printf '====' | head -c $(( (4 - ${#p} % 4) % 4 )))" | base64 -d 2>/dev/null | jq -c '{sub, sid}' 2>/dev/null || true
}

# carol's live Keycloak sessions: a JSON array, or fails when the API is unreachable.
_wa_sessions() {
  local id
  id="$(kc_user_id "$_wa_user")" || return 1
  [[ -n "$id" ]] || return 1
  kc_api GET "/$REALM/users/$id/sessions"
}

# Broken only when the saved browser state and Keycloak agree: the state holds a
# KEYCLOAK_IDENTITY cookie for carol, and Keycloak still has that session.
# Anything else is "stale": reported as unknown, with a reason, and scenario_fix
# clears it (scripts/fix.sh goes ahead on a detail that starts "stale:").
scenario_detect() {
  local sessions n claims sub sid id
  sessions="$(_wa_sessions 2>/dev/null)" || { printf 'unknown\tKeycloak admin API unreachable, or no user %s\n' "$_wa_user"; return; }
  n="$(jq length <<<"$sessions")"
  if [[ ! -e "$_wa_state" ]]; then
    if (( n == 0 )); then
      printf 'healthy\tno shared-PC browser state, and %s has no Keycloak session\n' "$_wa_user"
    else
      printf 'unknown\tstale: %s has %s Keycloak session(s) but there is no shared-PC browser state to match; scripts/fix.sh wrong-account ends them\n' "$_wa_user" "$n"
    fi
    return
  fi
  claims="$(_wa_cookie_claims)"
  if [[ -z "$claims" ]]; then
    printf 'unknown\tstale: the shared-PC browser state has no usable KEYCLOAK_IDENTITY cookie; scripts/fix.sh wrong-account removes it\n'; return
  fi
  sub="$(jq -r .sub <<<"$claims")" sid="$(jq -r .sid <<<"$claims")"
  id="$(kc_user_id "$_wa_user")"
  if [[ "$sub" != "$id" ]]; then
    printf 'unknown\tstale: the shared-PC browser state holds a Keycloak session for someone other than %s; scripts/fix.sh wrong-account removes it\n' "$_wa_user"; return
  fi
  if jq -e --arg sid "$sid" 'map(.id) | index($sid) != null' <<<"$sessions" >/dev/null; then
    printf 'broken\tthe shared PC holds %s'"'"'s Keycloak session, and Keycloak still has it (%s session(s) for %s)\n' "$_wa_user" "$n" "$_wa_user"
  else
    printf 'unknown\tstale: the shared-PC browser state holds a %s session that Keycloak no longer has (restart, or it idled out); scripts/fix.sh wrong-account removes it\n' "$_wa_user"
  fi
}

# One browser run, as test.sh does it: the tests container, as the demo user $1.
_wa_browser() { local user="$1"; shift; compose run --rm -T -e E2E_USER="$user" tests "$@"; }

scenario_break() {
  local out
  out="$(_wa_browser "$_wa_user" oidc-pc-signin --expect ok 2>&1)" || { echo "$out" >&2; die "could not sign $_wa_user in at the shared PC"; }
  grep -F '[oidc-pc-signin] carol' <<<"$out" || true
  [[ -s "$_wa_state" ]] || die "the shared PC's browser state was not saved"
  chmod 600 "$_wa_state"
}

# Sign carol out in the browser that holds her session, as she (or whoever
# found it) would, then delete the state file. A state file with nothing behind
# it, or a session with no state file (the stale cases), is cleared too: the
# browser sign-out is tried when there is state, and anything Keycloak still
# holds for carol is ended through the Admin API, as an admin would from
# Sessions in the console.
scenario_fix() {
  local out id
  if [[ -e "$_wa_state" ]]; then
    out="$(_wa_browser alice oidc-pc-signout --expect ok 2>&1)" || warn "the browser sign-out did not complete: $(tail -n 2 <<<"$out" | tr '\n' ' ')"
    rm -f "$_wa_state"
  fi
  id="$(kc_user_id "$_wa_user")"
  if [[ -n "$id" ]] && (( $(kc_api GET "/$REALM/users/$id/sessions" | jq length) > 0 )); then
    warn "$_wa_user still has a Keycloak session after the browser sign-out: ending it through the Admin API"
    kc_api POST "/$REALM/users/$id/logout" >/dev/null
  fi
}

# shellcheck disable=SC2329  # invoked by scripts/test.sh while broken
scenario_also_check() {
  local har jar id sessions roles
  har="$(find "$LAB_ROOT/test-results" -maxdepth 1 -name 'oidc-shared-pc-[0-9]*.har' -printf '%T@ %p\n' | sort -n | tail -n 1 | cut -d' ' -f2-)"
  [[ -n "$har" ]] || { echo "no oidc-shared-pc-*.har in test-results/"; return 1; }
  jar="${har%.har}-cookies.json"
  echo "evidence: ${har##*/}, ${jar##*/}"
  # 1. The HAR: the request to Keycloak carried its session cookies, and was
  #    answered with a redirect to the app. There is no login form POST at all.
  jq -er '[.log.entries[] | select(.request.url | test("/protocol/openid-connect/auth\\?"))][0]
      | select(([.request.cookies[].name] | index("KEYCLOAK_IDENTITY")) != null and .response.status == 302
               and (.response.redirectURL | test("/auth/callback")))
      | "GET " + (.request.url | sub("\\?.*"; "")) + " -> 302 to the app, sent with: " + ([.request.cookies[].name] | join(" "))' "$har" \
    || { echo "the HAR's authorisation request should carry KEYCLOAK_IDENTITY and be redirected straight to the app's callback"; return 1; }
  jq -e '[.log.entries[] | select(.request.method == "POST" and (.request.url | test("/login-actions/")))] | length == 0' "$har" >/dev/null \
    || { echo "the HAR holds a login form POST: someone signed in"; return 1; }
  echo "no login form POST in the HAR: nobody typed a password"
  # 2. The cookie jar: Keycloak's session was in it before the login started.
  jq -er '.steps[] | select(.step == "app") | [.cookies[].name] | select(index("KEYCLOAK_IDENTITY") != null)
      | "before the login, the jar already held: " + join(" ")' "$jar" \
    || { echo "the cookie summary should show KEYCLOAK_IDENTITY in the jar before the login"; return 1; }
  # 3. The page the app showed: carol's identity and none of alice's roles.
  roles="$(grep -o 'Realm roles</th><td><code>[^<]*' "${har%.har}.html" | sed 's/.*<code>//')" \
    || { echo "no Realm roles row in ${har##*/}'s saved page"; return 1; }
  echo "the app's page: email carol@idlab.example, realm roles: $roles"
  grep -qF 'carol@idlab.example' "${har%.har}.html" || { echo "the page should show carol"; return 1; }
  ! grep -qF 'lab-user' <<<"$roles" || { echo "carol's roles should not include lab-user"; return 1; }
  # 4. Keycloak: carol's session is one the PC left open, and alice has no login here.
  id="$(kc_user_id "$_wa_user")"
  sessions="$(kc_api GET "/$REALM/users/$id/sessions")" || return 1
  jq -er 'select(length == 1) | .[0] | "Keycloak sessions list for carol: 1 session, started " + (.start / 1000 | todate) + ", last access " + (.lastAccess / 1000 | todate) + ", clients: " + ([.clients[]] | join(" "))' <<<"$sessions" \
    || { echo "carol should have exactly one Keycloak session"; return 1; }
  log_has "$(date -u -d '-3 minutes' +%Y-%m-%dT%H:%M:%SZ)" keycloak 'type="LOGIN".*clientId="oidc-rp".*username="carol"' \
    | sed -E 's/(realmId|sessionId|userId|ipAddress|code_id|authSessionParentId|authSessionTabId)="[^"]*"/\1=.../g' \
    || { echo "no LOGIN event for carol"; return 1; }
}
