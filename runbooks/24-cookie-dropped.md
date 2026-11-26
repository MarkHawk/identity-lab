# 24 · Cookie dropped: signed in at Keycloak, then "Your session has expired"

| | |
|---|---|
| **Protocol** | SAML 2.0 Web SSO with HTTP-POST to the SP's assertion consumer service (`/saml/acs`), then the SP's own session cookie, `saml_sp_session`, on every later page. Browsers apply cookie rules before anything reaches the server: a cookie they refuse is never stored and never sent back. Since 2020, Chromium-based browsers refuse a cookie that says `SameSite=None` without also saying `Secure`. Keycloak, the SAML response, its signature and the SP's validation are all fine. |
| **Blast radius** | Every user of the one SP whose cookie setting changed, in every browser that enforces the rule (all Chromium-based ones: Chrome, Edge, Brave, Opera; see [Diagnosis](#diagnosis) for the others). Other apps on the same IdP, the SP behind the proxy (`:8184`, same code, its own settings) and Keycloak's own cookies are unaffected. |
| **Typical trigger** | A cookie setting changed for a good reason, with one line lost: `SameSite=None` added so the IdP's cross-site POST to the ACS carries the session (common advice for SAML apps), with `Secure` left out or left to a framework default that is off; `Secure` turned off because "TLS ends at the load balancer, so the app is on HTTP"; a proxy or gateway that rewrites cookie flags (nginx `proxy_cookie_flags`, an ingress annotation); an upgrade that changed a framework's cookie defaults. |
| **Lab** | `scripts/break.sh cookie-dropped` · `scripts/fix.sh cookie-dropped` (replaces `.state/saml-sp/session-cookie.conf`, the direct SP's session cookie settings, which it re-reads on every response, with one line: `SESSION_COOKIE_SAMESITE=None`. Secure then takes Flask's default, off. The SP isn't restarted, and nothing else changes.) |

## Symptom

Go to https://LAB_HOST:8181/ and click **Log in with SAML**. Keycloak's login page appears, the password is accepted, and the browser comes back to the SP, which says:

```
SAML 2.0 sample service provider
Your session has expired. Please log in again.
Log in with SAML
```

Click **Log in with SAML** again and there is no login page this time: Keycloak still has a valid session (its own cookies are fine), signs the user straight back in, and the SP shows the same message. That is the loop. Users describe it as *"it keeps sending me back to the login page"*, *"I log in, and it says my session expired straight away"*, or *"it works in Firefox but not in Chrome"* (or the reverse). The session didn't expire: it was never kept.

Nothing on the page and nothing in the browser **console** says why. Chromium reports a refused cookie in two other places in its developer tools (F12):

- **Network** → the `POST /saml/acs` request → **Cookies** tab: under *Response Cookies*, `saml_sp_session` is highlighted with a warning icon. Its tooltip says the cookie was blocked because it had `SameSite=None` without `Secure`.
- **Issues** (the tab, or the issue counter at the top right of DevTools): a cookie issue for `saml_sp_session` saying cookies marked `SameSite=None` must also be marked `Secure`.

**Every server's log says the login worked.** Keycloak logs a successful login event:

```
2026-11-24 17:38:48,980 INFO  [org.keycloak.events] (executor-thread-6) type="LOGIN", realmId="<realm ID>", realmName="idlab", clientId="https://idlab.home:8181/saml/metadata", userId="<alice's user ID>", sessionId="<session ID>", ipAddress="<browser>", auth_method="saml", redirect_uri="https://idlab.home:8181/saml/acs", consent="no_consent_required", code_id="<code ID>", username="alice", authSessionParentId="<ID>", authSessionTabId="<ID>"
```

The SP accepts the response, sets its cookie, and then sees the very next request arrive without it:

```
2026-11-24 17:38:48,493 INFO saml-sp event=saml_authn_request request_id=ONELOGIN_... user_agent='Mozilla/5.0 (X11; Linux x86_64) ... Chrome/153.0.0.0 Safari/537.36'
2026-11-24 17:38:49,103 INFO saml-sp event=saml_login_ok name_id=alice@idlab.example assertion_id=ID_...
2026-11-24 17:38:49,108 INFO saml-sp event=saml_session_missing path=/debug session_cookie=absent
```

`saml_login_ok` and then `session_cookie=absent` 5 ms later, from the same browser, is the signature of this fault. (`saml_authn_request` lines with `user_agent=idlab-status` are `scripts/status.sh` checking the scenario, not users.)

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  cookie-dropped                 broken   saml_sp_session is set with: HttpOnly; Path=/; SameSite=None

# The cookie as the SP sets it: attributes only, the value cut off
curl -sS -o /dev/null -D - --cacert certs/ca.crt -A idlab-status https://LAB_HOST:8181/login \
  | tr -d '\r' | grep -i '^set-cookie: saml_sp_session' | sed 's/=[^;]*;/=<value>;/'
#  set-cookie: saml_sp_session=<value>; HttpOnly; Path=/; SameSite=None      <- no Secure
#  healthy:    saml_sp_session=<value>; Secure; HttpOnly; Path=/; SameSite=Lax

# The servers' view: a good login, then a request with no session
docker compose logs --since 10m saml-sp | grep -E 'saml_login_ok|saml_session_missing'
docker compose logs --since 10m keycloak | grep 'type="LOGIN"'

# The setting itself
cat .state/saml-sp/session-cookie.conf
```

`scripts/test.sh` saves the browser's side of every login in `test-results/`, as a support engineer would get it from a customer. For the broken login, `saml-<time>.har`, `saml-<time>-cookies.json` and `saml-<time>-console.txt`:

```bash
# 1. The HAR: the ACS response sets the cookie, and its attributes say why it was refused
jq -r '.log.entries[] | select(.request.url | endswith("/saml/acs"))
  | "\(.request.method) \(.request.url) -> \(.response.status) \(.response.redirectURL)",
    (.response.headers[] | select(.name | ascii_downcase == "set-cookie") | "  Set-Cookie: \(.value)")' test-results/saml-<time>.har
#  POST https://idlab.home:8181/saml/acs -> 302 https://idlab.home:8181/debug
#    Set-Cookie: saml_sp_session=<redacted>; HttpOnly; Path=/; SameSite=None

# 2. The cookie jar back at the app: Keycloak's cookies are there, the SP's isn't
jq -c '.steps[] | {step, url, cookies: [.cookies[].name]}' test-results/saml-<time>-cookies.json
#  {"step":"keycloak","url":"https://idlab.home:8180/realms/idlab/protocol/saml","cookies":["AUTH_SESSION_ID","KC_AUTH_SESSION_HASH","KC_RESTART"]}
#  {"step":"back-at-app","url":"https://idlab.home:8181/","cookies":["AUTH_SESSION_ID","KC_AUTH_SESSION_HASH","KEYCLOAK_IDENTITY","KEYCLOAK_SESSION"]}

# 3. Why: what the browser said, and what the HAR and the jar say together
jq -c '.refusedByBrowser[] | {name, url, reasons: (.reasons // .exclusionReasons), source}' test-results/saml-<time>-cookies.json
#  {"name":"saml_sp_session","reasons":["SameSiteNoneInsecure"],"source":"browser: Chromium DevTools protocol, Network.responseReceivedExtraInfo"}
#  {"name":"saml_sp_session","url":"https://idlab.home:8181/saml/acs","reasons":["ExcludeSameSiteNoneInsecure"],"source":"browser: Chromium DevTools protocol, Audits.issueAdded (the Issues panel)"}
jq -c '.steps[] | select(.step == "back-at-app") | .inferredRefused[] | {name, setBy, sameSite, secure}' test-results/saml-<time>-cookies.json
#  {"name":"saml_sp_session","setBy":"POST https://idlab.home:8181/saml/acs -> 302","sameSite":"None","secure":false}

# 4. The console: empty. The refusal isn't logged there.
cat test-results/saml-<time>-console.txt
```

The refusal reasons (`refusedByBrowser`) come from Chromium's DevTools protocol, so the lab records them for Chromium only. The comparison in `inferredRefused` (a `Set-Cookie` in the HAR, then no such cookie in the jar) works for a HAR from any browser that kept its cookie headers (see below), and it's the one a support engineer can make from such a HAR alone: find the response that sets the app's session cookie, read its attributes, and check whether the next request to the app sends it in its `Cookie` header. Here it doesn't: `GET /debug` goes out with no `saml_sp_session`.

**A customer's default HAR can't show this fault.** Since Chrome 130, every Chromium-based browser (Chrome, Edge, Brave, Opera) exports a *sanitised* HAR by default: it removes the `Cookie`, `Set-Cookie` and `Authorization` headers and empties the cookie lists, which is exactly the evidence this needs. A HAR with them takes two steps in DevTools: **Settings** (the gear) → **Preferences** → **Network** → *Allow to generate HAR (with sensitive data)*, then **Export HAR (with sensitive data)** in the Network tab. That file holds live session cookies and, for SAML, the signed assertion.

So ask for evidence in this order (the questions below):

1. **A screenshot first.** The **Issues** tab, or the Network tab's **Cookies** view for the `POST /saml/acs` request, shows the refused cookie and why, with no secret in it.
2. **A HAR with sensitive data only if the screenshot isn't enough,** sent through a secure channel (not the ticket or email), captured in a test account if possible, and treated as a secret. Warn the customer it contains live session cookies, and ask them to **sign out of the app and the IdP straight after capturing it**, so those cookies stop working.
3. **Don't expect the console to help.** An empty console is normal for this fault: Chromium reports refused cookies under Issues and in the Network tab, not in the console.

## Diagnosis

1. **The login worked, the session didn't stick.** Keycloak's `LOGIN` event and the SP's `saml_login_ok` prove the IdP authenticated the user and the SP accepted the assertion. A request straight afterwards with no session cookie (`saml_session_missing ... session_cookie=absent`) means the browser didn't store or didn't send the cookie the SP had just set. Signs it's the browser and not the server: it starts at a change to the app's cookie settings, not to the IdP; Keycloak's own logins and other apps are fine; it depends on the browser; and the servers' logs show no error at all.
2. **Read the `Set-Cookie` attributes.** The browser decides from them alone:

   | `Set-Cookie` for the session | Chromium | Why |
   |---|---|---|
   | `Secure; HttpOnly; Path=/; SameSite=Lax` (healthy) | stored | |
   | `HttpOnly; Path=/; SameSite=None` (**this scenario**) | refused: `SameSiteNoneInsecure` | `SameSite=None` must come with `Secure` |
   | `Secure; HttpOnly; Path=/; SameSite=None` | stored | the usual fix for a cross-site POST |
   | `HttpOnly; Path=/; SameSite=Lax` (no Secure) | stored over HTTPS | allowed, but the cookie can then be sent over plain HTTP too |
   | `...; Domain=other.example` | refused: `InvalidDomain` | a cookie can only be set for the site that sets it |
   | `Secure` set by a page the browser reached over plain `http://` | refused (except on `localhost`) | the Secure rule; this lab has no plain-HTTP route, so it isn't reproduced |

   The first five were tried in the lab's Chromium (153); the last is the documented rule, not tested here. A cookie that's too large (over about 4 KB) or a path that doesn't cover the page are other ways for a cookie to "disappear" with the same symptom.
3. **Browsers differ.** This lab only tests Chromium. Chromium-based browsers have enforced "`SameSite=None` requires `Secure`" since 2020. Firefox and Safari have handled `SameSite` differently over the years and by version, so a customer saying *"it works in another browser"* is a clue, not a contradiction. The reliable test is the customer's own browser and version, with the developer tools open.
4. **Why `SameSite=None` gets set at all, and why it isn't needed here.** With the HTTP-POST binding, the IdP's page posts the SAML response to the ACS. When the IdP and the SP are on different sites (say `login.example-idp.com` and `app.example.com`), that's a cross-site POST, and a browser doesn't send a `SameSite=Lax` cookie with it. An SP that keeps the AuthnRequest ID (or the page to return to) in its session then loses it at the ACS, and `SameSite=None; Secure` is the usual fix. **In this lab every app is on one host, `LAB_HOST`, on different ports. Browsers treat that as the same site (the port isn't part of a site), so the IdP's POST counts as same-site and a `Lax` cookie is sent with it.** The lab reproduces the refused cookie, not the cross-site POST failure that the change was meant to fix.
5. **The SP accepted the response without checking `InResponseTo`.** The SP stores the ID of its AuthnRequest in its session and passes it to python3-saml when the response arrives. With the cookie refused there's no session, so the stored ID is missing, and python3-saml *skips* the `InResponseTo` check rather than failing it. The login goes through on the signature, audience, destination and timestamps alone. That's why this fault shows up as a lost session after a "successful" login instead of an error at the ACS. It also matters for security: an SP that doesn't tie the response to a request it sent accepts **unsolicited** responses, any validly signed response for it that a browser posts. That allows login CSRF (an attacker posts their own valid response into a victim's browser, so the victim works in the attacker's account) and makes a captured response replayable until it expires. Many SPs accept IdP-initiated logins on purpose, which have no `InResponseTo`, and then rely on short assertion lifetimes and replay caches instead. This lab's SP doesn't change its behaviour here; see [limitations](../docs/limitations.md).
6. **Contrast with runbook 15, the redirect loop.** Same complaint (*"it keeps looping"*), opposite cause:

   | | [15 · Redirect loop](15-redirect-loop.md) | 24 · Cookie dropped |
   |---|---|---|
   | Where it breaks | The server: the proxy stops sending `X-Forwarded-Proto` | The browser: it refuses the app's cookie |
   | When | Before any login: the first page never loads | After a successful login |
   | What the user sees | The browser's own error, `ERR_TOO_MANY_REDIRECTS` | The app's page, "Your session has expired" |
   | Keycloak | Never reached | `LOGIN` events, all successful |
   | Server logs | `force_https ... x_forwarded_proto=-`, about 20 per attempt | `saml_login_ok` then `saml_session_missing ... session_cookie=absent` |
   | Cookies | Not involved: clearing them doesn't help | The whole story: the HAR's `Set-Cookie` and the jar |
   | `curl` reproduces it | Yes: `curl -I` shows a 302 to the same URL | No: curl doesn't apply browser cookie rules |
   | Depends on the browser | No | Yes |

**Root cause, in one sentence for the customer:** the app's session cookie was changed to `SameSite=None` without `Secure`, a combination modern browsers refuse, so after each successful sign-in the browser throws the session away and the app asks the user to log in again.

## Fix

1. Give the cookie a combination browsers accept. In the lab:
   ```bash
   scripts/fix.sh cookie-dropped
   ```
   By hand, put both lines back in `.state/saml-sp/session-cookie.conf` (the SP reads it on the next response):
   ```
   SESSION_COOKIE_SAMESITE=Lax
   SESSION_COOKIE_SECURE=true
   ```
   If the app really needs `SameSite=None` (an IdP on another site posting to the ACS, or the app embedded in another site's frame), keep it **and** add `Secure`: `SameSite=None; Secure`. The app is served over HTTPS, so `Secure` costs nothing. Behind a TLS-terminating proxy, set `Secure` regardless of the scheme the app itself sees, or make sure the app trusts the proxy's `X-Forwarded-Proto` (runbook 15).
2. Verify: the curl above shows `Secure` (and `SameSite=Lax`, or `None` with `Secure`), a login lands on the SP's *SAML login succeeded* page, the SP logs `saml_login_ok` with no `saml_session_missing` after it, and `scripts/status.sh` shows `healthy`.
3. Users don't need to clear anything. The refused cookie was never stored, and Keycloak's own session was fine throughout: their next login works.

Don't fix it by telling users to change browser settings or use another browser, or by moving the session into the URL. The cookie's attributes are the app's to get right.

## Prevention

- **Treat cookie attributes as part of the release.** Test a login in a current Chromium-based browser and in Firefox after any change to cookie settings, proxy cookie rewriting or the app's framework version, with an automated browser test where possible (as `scripts/test.sh` does).
- **Set `SameSite` and `Secure` together, explicitly,** rather than relying on framework defaults, which differ (Flask's `SESSION_COOKIE_SECURE` is off by default) and change between versions.
- **Log the session's absence, not just failures.** A "protected page without a session" line, next to the login success before it, is what turns *"it just sends me back"* into a diagnosis. This SP's `saml_session_missing` says whether a cookie was sent at all, never its value.
- **Keep the SAML request check.** Store the AuthnRequest ID somewhere that survives a lost cookie (for example `RelayState` pointing at server-side state), or fail the login when it's missing, so a session problem shows up at the ACS instead of being skipped silently.

## Questions I'd ask the customer

1. Which browser and version (Chrome's *About* page or `chrome://version`, Edge's `edge://version`, Firefox's *About Firefox*)? Does it happen in every browser you've tried, or only some? On every device?
2. Does it fail for every user of this app, or only some? Do other apps that sign in through the same IdP work?
3. After you sign in, does the app ask you to log in again straight away, and does the second login skip the password?
4. Can you send a screenshot of the developer tools (F12) **Issues** tab after one failed attempt, or of the Network tab's **Cookies** view for the `/saml/acs` request (**Preserve log** on)? It shows the cookie the browser refused and why. The **Console** will probably be empty: that's expected for this fault, not a sign that nothing is wrong.
5. Only if the screenshot isn't enough: can you export a HAR **with sensitive data** (DevTools **Settings** → **Preferences** → **Network** → *Allow to generate HAR (with sensitive data)*, then **Export HAR (with sensitive data)**; the default export since Chrome 130 leaves out the cookies)? Send it through a secure channel, not the ticket, and use a test account if you can. It contains live session cookies: sign out of the app and the IdP straight after capturing it, so they stop working.
6. What changed recently in the app's cookie or session settings, its framework version, or a proxy, load balancer or gateway in front of it (anything that rewrites cookies)?
7. Is the app served over HTTPS end to end, or does TLS end at a proxy or load balancer in front of it?
