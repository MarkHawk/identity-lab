# 25 · Login page left open too long: "Your login attempt timed out" (and the bookmarked login page)

| | |
|---|---|
| **Protocol** | OIDC authorisation code flow (SAML is the same at this step). When the app sends the browser to Keycloak, Keycloak starts a *login session* (an "authentication session") for that visit, keeps it on the server, and gives the browser a cookie, `AUTH_SESSION_ID`, to find it again. The login page's form can only be submitted while that session lives. The realm's **login timeout** (`accessCodeLifespanLogin`, 30 minutes by default) is how long it lives. Nothing is wrong with the user's password, the app, or the servers' health. |
| **Blast radius** | Every user who leaves a login page open longer than the realm's login timeout, in every app and browser. With the lab's 20 s timeout that's anyone who pauses; with a default 30 minutes it's a few people a day (a phone call, a lunch break, a laptop closed on a login page, a tab restored after a restart). A user who signs in straight away is unaffected. Separately, **a saved Keycloak URL fails whatever the timeout is** (see [the bookmark variant](#the-bookmarked-login-page-variant)). |
| **Typical trigger** | Someone shortened the login timeout, often with the other session settings, as part of hardening (the lab's 20 s stands for "a few minutes" in a real realm that a slow password manager or an MFA push approval then overruns). Or nothing changed at all, and a user kept a login page open overnight, or bookmarked the login page itself. |
| **Lab** | `scripts/break.sh login-timeout` · `scripts/fix.sh login-timeout` (sets the realm's `accessCodeLifespanLogin` to 20 s and back to 1800 s through the Admin REST API, sending the whole realm as the admin console does; nothing else changes, and no `--fresh` is needed. The Admin API accepts 1 s upwards and refuses 0 or less with `AccessCodeLifespanLogin or AccessCodeLifespanUserAction cannot be 0`. The admin console may enforce a larger minimum: not tried.) |

## Symptom

Open an app (`https://LAB_HOST:8182/`), click **Log in with OIDC**, and leave Keycloak's login page alone for more than 20 seconds (a healthy realm allows 30 minutes). Then type the username and password and press **Sign In**. Keycloak doesn't sign you in. It shows the login form again, empty, with a notice above it:

```
Your login attempt timed out. Login will start from the beginning.
```

Typing the details again, straight away, works. Users say *"it didn't accept my password the first time"*, *"I had to log in twice"*, or *"it said my login timed out"*. Some report it as a wrong password, because the form is back and empty.

Other identity providers word it differently; this runbook only describes Keycloak's.

**Browsers show nothing different:** it is a normal page. The browser console is empty, and there is no cookie refusal: the cookie is sent and the server says it no longer has the session behind it.

### In the logs

Keycloak logs the failure as a warning. It cannot say who it was, because the user hadn't signed in yet:

```
2026-11-24 18:33:58,196 WARN  [org.keycloak.events] (executor-thread-36) type="LOGIN_ERROR", realmId="<realm ID>", realmName="idlab", clientId="oidc-rp", userId="null", ipAddress="<browser>", error="expired_code", code_id="<code ID>"
```

`error="expired_code"` with `userId="null"` is the signature. The app logs nothing: it never saw the user again. (A successful login logs `type="LOGIN"` at info; its absence next to this line is the other half of the story.)

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  login-timeout                  broken   realm login timeout (accessCodeLifespanLogin): 20 s, healthy is 1800 s

# The realm's settings (Admin console: Realm settings -> Sessions -> Login timeout; the lab sets it through the API)
bash -c 'source scripts/lib.sh; load_env; kc_api GET /idlab | jq "{accessCodeLifespanLogin, accessCodeLifespanUserAction, ssoSessionIdleTimeout}"'
#  {"accessCodeLifespanLogin": 20, "accessCodeLifespanUserAction": 300, "ssoSessionIdleTimeout": 1800}

# Who changed the realm, and when (admin events are on in this realm, without details)
bash -c 'source scripts/lib.sh; load_env; kc_api GET "/idlab/admin-events?operationTypes=UPDATE&resourceTypes=REALM&max=5"' \
  | jq -r '.[] | "\(.time / 1000 | todate) \(.operationType) \(.resourceType) by \(.authDetails.userId) from \(.authDetails.ipAddress)"'

# Keycloak's view of the failed attempts
docker compose logs --since 10m keycloak | grep -E 'error="(expired_code|cookie_not_found)"'
```

`scripts/test.sh` saves the browser's side of every login in `test-results/`. For the stale login, `oidc-stale-<time>.har`, `oidc-stale-<time>-cookies.json` and `oidc-stale-<time>-console.txt`:

```bash
# 1. The HAR: the login page, then the form POST 31 s later, and where Keycloak sent the browser
jq -r '.log.entries[] | select(.request.url | test("openid-connect/auth\\?|login-actions/authenticate"))
  | select(.request.url | test("resources") | not)
  | "\(.startedDateTime) \(.request.method) \(.request.url | sub("\\?.*"; "")) -> \(.response.status) cookies sent: \([.request.cookies[].name] | join(","))"' test-results/oidc-stale-<time>.har
#  2026-11-24T18:33:27.855Z GET  https://idlab.home:8180/realms/idlab/protocol/openid-connect/auth -> 200 cookies sent: oidc_rp_session
#  2026-11-24T18:33:58.191Z POST https://idlab.home:8180/realms/idlab/login-actions/authenticate -> 302 cookies sent: AUTH_SESSION_ID,KC_AUTH_SESSION_HASH,KC_RESTART,oidc_rp_session
#  2026-11-24T18:33:58.198Z GET  https://idlab.home:8180/realms/idlab/login-actions/authenticate -> 200 cookies sent: AUTH_SESSION_ID,KC_AUTH_SESSION_HASH,KC_RESTART,oidc_rp_session

# 2. The POST's redirect goes back to the login form, not to the app (there is no request to /auth/callback at all)
jq -r '.log.entries[] | select(.request.method == "POST") | .response.redirectURL | sub("\\?.*"; "")' test-results/oidc-stale-<time>.har
#  https://idlab.home:8180/realms/idlab/login-actions/authenticate

# 3. The cookie jar: the login-session cookie is there, but no KEYCLOAK_IDENTITY (nobody signed in)
jq -c '.steps[] | {step, cookies: [.cookies[].name]}' test-results/oidc-stale-<time>-cookies.json
#  {"step":"keycloak","cookies":["AUTH_SESSION_ID","KC_AUTH_SESSION_HASH","KC_RESTART","oidc_rp_session"]}
#  {"step":"end","cookies":["AUTH_SESSION_ID","KC_AUTH_SESSION_HASH","KC_RESTART","oidc_rp_session"]}

# 4. The console: empty. Nothing is refused, nothing errors.
cat test-results/oidc-stale-<time>-console.txt
```

What the HAR proves, and how to read it without the lab: **the gap between the login page's `GET` and the form's `POST`** (here 31 s, far above the 20 s limit), **the cookie names the POST carried** (`AUTH_SESSION_ID` is there: the browser did its part), and **the answer** (a 302 back to `login-actions/authenticate`, a 200 form again, never a redirect to the app's callback). A healthy login's POST is answered with a 302 to the app's `/auth/callback`.

**A customer's default HAR is sanitised, as in [runbook 24](24-cookie-dropped.md#where-to-look).** Chromium-based browsers since Chrome 130 remove `Cookie` and `Set-Cookie` headers from the HAR they export unless the person asks for sensitive data, so the cookie *names* in step 1 won't be there. What a default HAR still shows is the timing, the URLs and the status codes: the gap between the login page and the POST, and the POST answered by a redirect to the login form instead of the app. That's enough for this fault, so **don't ask for a HAR with sensitive data here**. Ask for the default one, or for the time the page was opened and the time the user pressed **Sign In**.

## Diagnosis

1. **The password isn't the problem.** A wrong password gives *Invalid username or password.* (the notice [runbook 22](22-mfa-lockout.md) also shows). This gives a different notice and `error="expired_code"`, `userId="null"`: Keycloak rejected the *page*, before it looked at the password.
2. **Time between the two requests.** Compare the login page's `GET` and the form's `POST` (HAR), or ask how long the page was open. Anything over the realm's login timeout fits. Keycloak counts from when the login session started, not from the last keystroke.
3. **Which cookie wording.** Two Keycloak messages look alike and mean different things:

   | What the user sees | What the server found | Keycloak event | Usual cause |
   |---|---|---|---|
   | Login form again: *Your login attempt timed out. Login will start from the beginning.* | The cookie was sent; the login session behind it has expired | `expired_code` | The page was open too long (**this scenario**) |
   | Error page, HTTP 400: *We are sorry... Restart login cookie not found. It may have expired; it may have been deleted or cookies are disabled in your browser. If cookies are disabled then enable them. Click Back to Application to login again.* | No login cookie came with the request at all | `cookie_not_found` | A saved login URL opened in another browser or after the cookies were cleared; cookies blocked; a login started in one browser and finished in another |

   Both were seen in the lab's Chromium. The **cookie names in the request** (a full HAR, or the browser's Network tab) tell them apart: the first has `AUTH_SESSION_ID`, the second has none.
4. **It isn't a server fault.** Keycloak, the app and the network answered every request. The only change is a setting, and the setting can be right. 30 minutes is plenty for a person; 20 seconds is not.
5. **Contrast with runbook 24.** Same family ("it sent me back to the login page"), different cause:

   | | [24 · Cookie dropped](24-cookie-dropped.md) | 25 · Login timeout |
   |---|---|---|
   | When it fails | After a successful sign-in | Before one: the password is never checked |
   | Keycloak | `LOGIN`, successful | `LOGIN_ERROR`, `expired_code`, `userId="null"` |
   | The browser's cookie | Refused: never stored | Stored and sent; the server has forgotten the session |
   | Retrying | Fails the same way | Works, if the user types straight away |

**Root cause, in one sentence for the customer:** the sign-in page was open for longer than the service allows, so the service had already thrown away that sign-in attempt, and starting again (from the app, not from the old page) works.

## The bookmarked-login-page variant

A user bookmarks Keycloak's login page, not the app's, and uses the bookmark every morning. It looks like a timeout (the page is "old"), but it isn't, and **it fails however long the timeout is**: in the lab it fails for a login page opened a second earlier, which no timeout setting could have expired. Two different URLs get bookmarked, and they fail differently. Both were tried in the lab (`oidc-bookmark`, with the browser's cookies cleared, standing for another browser or a cleaned-up profile):

| Bookmarked URL | Where it comes from | What the user sees |
|---|---|---|
| `.../realms/idlab/login-actions/authenticate?session_code=...&tab_id=...` | The address bar after a wrong password, a timeout, or a page the user reloaded | HTTP 400: *Restart login cookie not found...* Keycloak logs `error="cookie_not_found"` |
| `.../realms/idlab/protocol/openid-connect/auth?response_type=code&client_id=...&state=...` | The address bar on the first login page | A fresh login form, and the password **is** accepted by Keycloak. Then the app shows *OIDC login failed. CSRF Warning! State not equal in request and response.* (`mismatching_state`), because the app remembers the `state` it sent in its own cookie and this isn't that login |

In the second case the HAR shows Keycloak's sign-in succeed (`KEYCLOAK_IDENTITY` in the jar) and the app's `/auth/callback` answer 401 with no app cookie sent. It sometimes works: in the lab, reopening the same login URL in the *same* browser, straight after the login that created it, signed in fine, because the app's own cookie still held that `state`. The next login attempt from the app replaces it, and the bookmark stops working. That inconsistency is why users say *"it works sometimes"*.

A bookmark also carries one-time values (`session_code`, `client_data`, `state`): don't ask the customer to paste the URL into the ticket. Ask them to say which kind of page it is, and read the path only.

## Fix

1. **For the user: start from the app, not from the old page.** Close the login tab and open the application's own address (or its bookmark), click **Log in** and sign in without leaving the page. This is the answer for the bookmarked login page too: replace the bookmark with the app's URL. No server change is needed or wanted for a user who left a page open or used a bookmark. The server is behaving as designed.
2. **For the realm, only if many users hit it, or the timeout is far too short.** In the lab:
   ```bash
   scripts/fix.sh login-timeout
   ```
   By hand: *Realm settings → Sessions → Login timeout* in the admin console (the field's wording is from memory, not checked in this lab), or `accessCodeLifespanLogin` through the Admin API. Choose a value longer than the slowest legitimate login, including an MFA approval on a phone (minutes, not seconds). The default is 30 minutes. A very long timeout isn't free: each open login page holds a login session on the server until it expires, and a stolen login URL stays usable that long. Don't set it to hours to hide a different problem.
3. Verify: `scripts/status.sh` shows `login-timeout` healthy, and a login that waits 30 s on the login page now signs in.
4. A user whose attempt timed out doesn't need to clear cookies, change browsers or reset a password.

## Prevention

- **Change session timeouts deliberately.** *Login timeout*, *Login action timeout* (`accessCodeLifespanUserAction`, 5 minutes here, which covers the time between the steps of a login such as a code form; not tested in this lab) and the SSO session timeouts are different settings with different jobs. Test a slow login, a password manager and an MFA approval after any change.
- **Put the app's own address on bookmarks, start pages and email links**, never the IdP's login page.
- **Log what the user can't tell you.** `userId="null"` means the log can't name the user: the support engineer needs the time and the client (`clientId`) from the event, and the time the user pressed the button.
- **Tell users what the notice means.** *"Your login attempt timed out. Login will start from the beginning."* is Keycloak asking for the password again. Many users read it as a failure of their account.

## Questions I'd ask the customer

1. What exactly does the page say? (The exact wording tells *timed out* from *cookie not found*.) Is it the login form again with a notice, or an error page?
2. Did you leave the login page open for a while before signing in: a phone call, a meeting, lunch? How long, roughly, and at what time did you press **Sign In**?
3. Did you start from the application's address, or from a bookmark? **Was it a bookmark of the login page itself** (the address starts with the sign-in service's name, not the app's)? What does the address bar start with?
4. If you try again straight away, from the application's address, does it work?
5. Does it happen to everyone, or only people who leave the page open? Is it new, and did anything change in the sign-in service's session settings recently?
6. Is it always the same browser or device? Do you use a password manager that waits for something, or an MFA approval on your phone before the form submits?
7. Only if the above isn't enough: can you send the **default** HAR (not the one with sensitive data) of one failed attempt, with the time you opened the page? It shows the gap and the answer, and holds no cookies.
