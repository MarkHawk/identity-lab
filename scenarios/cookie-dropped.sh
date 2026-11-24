# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The SAML SP's session cookie is changed to SameSite=None, as advice for
# SAML apps often says: the IdP's POST to /saml/acs comes from another site,
# and a browser doesn't send a SameSite=Lax cookie with it. The Secure line
# is dropped in the same edit, and the framework's default for it is off.
# Browsers refuse a SameSite=None cookie that isn't Secure. Chromium says
# nothing on the page or in the console (DevTools lists it under Issues).
# Keycloak logs a successful LOGIN, the SP accepts the response, logs
# saml_login_ok and sets its session cookie, the browser throws the cookie
# away, and the next page has no session: "Your session has expired". Logging
# in again goes straight through Keycloak, whose own cookies are fine, and
# ends in the same place. The SP behind the proxy has its own settings.
SCENARIO_SUMMARY="the SAML SP's session cookie is SameSite=None without Secure: browsers refuse it"
SCENARIO_RUNBOOK="runbooks/24-cookie-dropped.md"
SCENARIO_APP=saml
SCENARIO_UNAFFECTED="saml-proxy alice"
SCENARIO_EXPECT="Your session has expired. Please log in again."
SCENARIO_SEEN_AT="on the SP's start page, straight after signing in at Keycloak. The refused cookie is in the browser's developer tools (F12): Network, the /saml/acs response's Cookies, and Issues"
SCENARIO_LOG='saml-sp event=saml_session_missing path=/debug session_cookie=absent'
SCENARIO_ALSO="Keycloak and the SP logged a successful login, and the browser evidence shows the cookie set, refused (SameSiteNoneInsecure) and missing from the jar"

_cd_file="$STATE_DIR/saml-sp/session-cookie.conf"
_cd_default="$LAB_ROOT/apps/saml-sp/session-cookie.conf"

# The attributes of the session cookie the SP really sets, never its value.
# /login is the one page that sets it without a login; the probe's user agent
# (idlab-status) is on the SP's saml_authn_request line, so it can be told
# from a browser's login.
_cd_live() {
  curl -sS -o /dev/null -D - -A idlab-status --cacert "$CERTS_DIR/ca.crt" \
    --resolve "$LAB_HOST:$SAML_SP_PORT:127.0.0.1" "https://$LAB_HOST:$SAML_SP_PORT/login" \
    | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: saml_sp_session=[^;]*//p' | sed 's/^; //'
}

scenario_detect() {
  local attrs lower
  attrs="$(_cd_live 2>/dev/null)" || { printf 'unknown\tthe SAML SP is unreachable\n'; return; }
  [[ -n "$attrs" ]] || { printf 'unknown\tthe SAML SP set no saml_sp_session cookie on /login\n'; return; }
  lower="${attrs,,}"
  if [[ "$lower" == *"samesite=lax"* && "$lower" =~ (^|;\ *)secure(;|$) ]]; then
    printf 'healthy\tsaml_sp_session is set with: %s\n' "$attrs"
  else
    printf 'broken\tsaml_sp_session is set with: %s\n' "$attrs"
  fi
}

# Re-read by the SP on every response: no restart, like a config reload.
_cd_set() { cat >"$_cd_file.tmp" && chmod 644 "$_cd_file.tmp" && mv "$_cd_file.tmp" "$_cd_file"; }
scenario_break() {
  _cd_set <<'CONF'
# The SAML SP's session cookie settings, re-read on every response.
# Changed by scenarios/cookie-dropped.sh: SameSite=None, so the IdP's POST to
# /saml/acs, which comes from another site, carries the session cookie.
SESSION_COOKIE_SAMESITE=None
CONF
}
scenario_fix() { _cd_set <"$_cd_default"; }

# shellcheck disable=SC2329  # invoked by scripts/test.sh while broken
scenario_also_check() {
  local har jar logs kc
  har="$(find "$LAB_ROOT/test-results" -maxdepth 1 -name 'saml-[0-9]*.har' -printf '%T@ %p\n' | sort -n | tail -n 1 | cut -d' ' -f2-)"
  [[ -n "$har" ]] || { echo "no saml-*.har in test-results/"; return 1; }
  jar="${har%.har}-cookies.json"
  echo "evidence: ${har##*/}, ${jar##*/}"
  # 1. The HAR: the ACS response sets the cookie, SameSite=None, not Secure.
  jq -er '[.log.entries[] | select(.request.url | test("/saml/acs$")) | .response.headers[]
      | select(.name | ascii_downcase == "set-cookie") | .value | select(startswith("saml_sp_session="))][0]
      | select(test("SameSite=None"; "i") and (test("(^|; *)Secure(;|$)"; "i") | not))' "$har" \
    || { echo "no Set-Cookie for saml_sp_session, SameSite=None without Secure, on the /saml/acs response"; return 1; }
  # 2. Chromium says it refused it, and why.
  jq -er '[.refusedByBrowser[] | select(.name == "saml_sp_session")
      | ((.reasons // []) + (.exclusionReasons // []))[]] | unique | join(" ")
      | select(test("SameSiteNoneInsecure"))' "$jar" \
    || { echo "the browser reported no refusal of saml_sp_session for SameSiteNoneInsecure"; return 1; }
  # 3. It never reached the jar, and the Set-Cookie comparison says so too.
  jq -er '.steps[] | select(.step == "back-at-app")
      | select(([.cookies[].name] | index("saml_sp_session")) == null)
      | [.inferredRefused[].name] | select(index("saml_sp_session") != null) | "back at the app, not in the jar: " + join(" ")' "$jar" \
    || { echo "saml_sp_session is in the jar back at the app, or wasn't inferred as refused"; return 1; }
  # 4. The servers saw a successful login.
  logs="$(compose logs --no-log-prefix --since 2m saml-sp)"
  grep -m1 -E 'event=saml_login_ok ' <<<"$logs" | sed -E 's/(name_id|assertion_id)=[^ ]+/\1=.../g' \
    || { echo "no saml_login_ok in the SP's log"; return 1; }
  kc="$(compose logs --no-log-prefix --since 2m keycloak)"
  grep -m1 -oE "type=\"LOGIN\", realmId=\"[^\"]*\", realmName=\"$REALM\", clientId=\"https://[^\"]+:$SAML_SP_PORT/saml/metadata\"" <<<"$kc" \
    || { echo "no successful LOGIN event for the SAML SP in Keycloak's log"; return 1; }
}
