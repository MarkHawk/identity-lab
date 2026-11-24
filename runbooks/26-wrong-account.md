# 26 · Signed in as the wrong account: "it's showing someone else's name"

| | |
|---|---|
| **Protocol** | OIDC with single sign-on (SAML Web SSO works the same way in principle; only OIDC is reproduced in the lab). When the user clicks **Log in**, the app sends the browser to the identity provider. If the browser already holds a valid IdP session, the IdP doesn't ask for a password: it sends the browser straight back with a login for **whoever that session belongs to**. Keycloak's session lives in cookies (`KEYCLOAK_IDENTITY`, `KEYCLOAK_SESSION`) for the IdP's address, separate from the app's own session cookie. |
| **Blast radius** | One browser profile: the person who opens the app at a PC where someone else left the IdP signed in. Shared, hot-desk, kiosk and meeting-room PCs, a family laptop, a support engineer's own machine after helping a user. Nothing else is affected: other users, other PCs and other browsers, including a private window on the same PC, sign in normally. |
| **Typical trigger** | The previous person clicked **Log out** in the app, which ended only the app's session, not the IdP's. (Some apps' log out ends their own session only. This lab's **Clear local session** button does the same.) Or they closed the tab, or locked the PC, or left the browser open. Single sign-on is designed to keep that session until it idles out or is ended. |
| **Lab** | `scripts/break.sh wrong-account` · `scripts/fix.sh wrong-account`. The lab can't reach anyone's browser, so it keeps a stand-in for the shared PC: the saved browser state `.state/browser/shared-pc.json` (Keycloak's cookies only; cookie values, so mode 0600, gitignored). `break` signs carol in with the test browser, clicks **Clear local session** and leaves her Keycloak session open. `fix` signs carol out of Keycloak in that browser by Keycloak's own logout page, clicking through its confirmation as a person would, then **deletes the state file**, so no cookie value stays on disk. A login in a fresh browser (any other PC) is unaffected. |

## Symptom

alice goes to a shared PC, opens the app (`https://LAB_HOST:8182/`) and clicks **Log in with OIDC**. She expects Keycloak's login page. There isn't one: the browser flashes and she is in, on the page that says *OIDC login succeeded*, but it shows:

```
Subject (sub)   <carol's user ID>
Email           carol@idlab.example
Realm roles     default-roles-idlab, offline_access, uma_authorization
```

She is carol. In a real app the symptom depends on what the app does with the identity:

- **A name or avatar that isn't hers** in the top right, or a greeting for someone else. The quickest way to spot it.
- **"Access denied", "You don't have permission", an empty dashboard, or menu entries missing**, because carol has no role in the app (here carol has no `lab-user` role, so none of alice's access, and alice's `lab-admin` is gone). The user says *"my access has been taken away"*.
- **Someone else's data**, orders, mail or settings. This is the serious variant: a privacy incident, not just a support ticket. Whatever alice does is recorded as carol.

The lab's sample apps don't enforce roles, so they show the wrong identity but never an access-denied page. A real app would deny.

Users say *"it didn't ask for my password"*, *"it logged me in as someone else"*, *"I don't have my admin menu any more"* or *"I'm in the wrong account"*.

**No server is faulty.** Every request succeeds, and every log line is a good login.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer (the lab's detect needs the saved browser state AND Keycloak's live session to agree;
# one without the other is reported as "unknown ... stale: ..." with the reason)
scripts/status.sh
#  wrong-account                  broken   the shared PC holds carol's Keycloak session, and Keycloak still has it (1 session(s) for carol)

# Keycloak's sessions list for the user the page showed (Admin console: Sessions, or the user's Sessions tab)
bash -c 'source scripts/lib.sh; load_env; kc_api GET "/idlab/users/$(kc_user_id carol)/sessions"' \
  | jq '.[] | {username, ipAddress, start: (.start / 1000 | todate), lastAccess: (.lastAccess / 1000 | todate), clients}'
#  {"username":"carol","ipAddress":"<browser>","start":"2026-11-24T18:43:48Z","lastAccess":"2026-11-24T18:43:50Z","clients":{"<client ID>":"oidc-rp"}}

# Keycloak's log: a LOGIN for carol, no password step, and the SAME sessionId as her earlier login
docker compose logs --since 10m keycloak | grep 'type="LOGIN"' | grep 'username="carol"'

# The app's log: sub, preferred_username and email of the identity it accepted
docker compose logs --since 10m oidc-rp | grep oidc_login_ok
#  ... event=oidc_login_ok sub=<carol's user ID> preferred_username=carol email=carol@idlab.example iss=https://idlab.home:8180/realms/idlab elapsed=0.09s
```

On the app's page, **ID token claims (validated)** shows the same `sub` and `preferred_username`. Compare them with who the user says they are.

`scripts/test.sh` saves the browser's side of every login in `test-results/`. For the shared-PC login, `oidc-shared-pc-<time>.har`, `...-cookies.json` and `...-console.txt`:

```bash
# 1. The HAR: the authorisation request went out WITH Keycloak's session cookies and came straight back with a 302 to the app
jq -r '.log.entries[] | select(.request.url | test("openid-connect/auth\\?"))
  | "\(.request.method) \(.request.url | sub("\\?.*"; "")) -> \(.response.status) \(.response.redirectURL | sub("\\?.*"; ""))  cookies sent: \([.request.cookies[].name] | join(","))"' test-results/oidc-shared-pc-<time>.har
#  GET https://idlab.home:8180/realms/idlab/protocol/openid-connect/auth -> 302 https://idlab.home:8182/auth/callback  cookies sent: AUTH_SESSION_ID,KC_AUTH_SESSION_HASH,KEYCLOAK_IDENTITY,KEYCLOAK_SESSION,oidc_rp_session

# 2. ...and no login form was ever posted
jq '[.log.entries[] | select(.request.method == "POST" and (.request.url | test("/login-actions/")))] | length' test-results/oidc-shared-pc-<time>.har
#  0

# 3. The cookie jar already held Keycloak's session before the login started
jq -c '.steps[] | {step, cookies: [.cookies[].name]}' test-results/oidc-shared-pc-<time>-cookies.json
#  {"step":"app","cookies":["AUTH_SESSION_ID","KC_AUTH_SESSION_HASH","KEYCLOAK_IDENTITY","KEYCLOAK_SESSION"]}
#  {"step":"back-at-app","cookies":["AUTH_SESSION_ID","KC_AUTH_SESSION_HASH","KEYCLOAK_IDENTITY","KEYCLOAK_SESSION","oidc_rp_session"]}

# 4. The console: empty. Nothing was refused or failed.
cat test-results/oidc-shared-pc-<time>-console.txt
```

**A customer's default HAR** (a sanitised one, as in [runbook 24](24-cookie-dropped.md#where-to-look)) has no cookie names, so step 1's "cookies sent" and step 3 won't be there. Steps 1 and 2 still prove most of it without them: the authorisation request is answered with a **302 straight to the app's callback**, and **there is no `POST` to `login-actions`**. A normal first login always has one. **Don't ask for a HAR with sensitive data for this**: it would hold the previous person's live session cookies as well as the user's. The user's screenshot of the page showing the wrong name is better evidence, and holds no secrets.

## Diagnosis

1. **Whose name is it?** Ask the user what name the app shows (top right, in most apps). If it isn't theirs, it's this fault or a deeper one (below). In the lab, the page's **Email** row and the ID token claims say it.
2. **No login form, no password.** The user says it didn't ask for a password. In the HAR there is no form `POST`; in Keycloak's log there's a `LOGIN` event but no failed or earlier step for that attempt.
3. **The Keycloak session is older than the login.** In the sessions list, the session's *start* is before the user's attempt, and the `LOGIN` event's `sessionId` matches an earlier `LOGIN` for the same person. A real login makes a new session. A silent one attaches to the existing session.
4. **Only this PC.** The same user at another PC, or in a private window on this one, signs in normally and as themselves. A different user at this PC lands in the same wrong account. That separates this from a wrong user mapping in the IdP or app, which follows the user to every PC.
5. **What it is not.**

   | Looks like | How it differs |
   |---|---|
   | A wrong role or group mapping | The user is *themselves*, with the wrong roles, on every PC. Here `sub` and `preferred_username` belong to someone else. |
   | A duplicate, merged or shared account | The wrong identity follows the *user* to every browser. Here it follows the *PC*. |
   | A bug or caching in the app | The app logged `oidc_login_ok` for exactly the identity Keycloak sent. Keycloak's `LOGIN` event names the same user. |

6. **How long it lasts.** The lab's Keycloak keeps a session until it idles for 30 minutes (`ssoSessionIdleTimeout` 1800 s), or for at most 10 hours in total (`ssoSessionMaxLifespan` 36000 s), whichever comes first, and each silent login moves the session's *lastAccess* on (seen in the sessions list), so **a busy shared PC can keep the previous person's session alive**. The `KEYCLOAK_IDENTITY` cookie is a session cookie (no expiry set, seen in the lab's Chromium), so a browser that really closes drops it. Whether yours does depends on the browser's *continue where you left off* setting, which the lab didn't test.

**Root cause, in one sentence for the customer:** the last person to use this computer signed out of the app but not of the sign-in service, so when you opened the app the sign-in service recognised the browser and signed you in as them without asking for a password.

## Fix

1. **Sign the wrong user out of the identity provider, in that browser.** In the lab:
   ```bash
   scripts/fix.sh wrong-account
   ```
   which does what a person would: opens Keycloak's logout page, `https://LAB_HOST:8180/realms/idlab/protocol/openid-connect/logout`. With no `id_token_hint`, which an app's logout would normally supply, **Keycloak doesn't log out straight away**: it shows a page titled *Logging out* that asks **Do you want to log out?** with a **Logout** button. That page is what the user will see. Clicking **Logout** shows *You are logged out*. Then the app's **Log in** brings up Keycloak's login form, and the right user signs in. (This is the lab's Keycloak 26; another IdP or version may skip the confirmation or word it differently.)
2. **Quicker for the user:** open the app in a **private/incognito window**. It has no IdP cookies, so it always asks for a password. Close the window after.
3. **If the user can't reach the browser, or the PC is unattended:** an admin ends the session: *Sessions* in the admin console (sign out), or `POST /admin/realms/idlab/users/<id>/logout` (the lab's `fix.sh` does this too for a session that has no browser state to match). That signs the person out everywhere, on every PC, not just this one, which may surprise them.
4. Verify: `scripts/status.sh` shows `wrong-account` healthy, and **Log in** at that PC shows Keycloak's login form.
5. **Treat it as a privacy event if the wrong account saw or changed anything.** What alice did as carol is in carol's audit trail. Tell carol, and the app's owner, with the time window.

Don't fix it by resetting the user's password, deleting their account, or clearing the app's cookies: none of that touches the IdP's session.

## Prevention

- **Make the app's Log out end the IdP session too.** Send the browser to the IdP's end-session endpoint (RP-initiated logout, with `id_token_hint` and a `post_logout_redirect_uri`). This lab's **Clear local session** deliberately doesn't, to reproduce the fault. Behaviour of other apps was not tested.
- **Shorter idle and maximum session timeouts on shared PCs**, and browsers that don't restore sessions on shared PCs (guest or kiosk mode, or private windows by policy).
- **Ask for a fresh password for sensitive apps.** OIDC lets an app ask the IdP to re-authenticate (`prompt=login`, or a `max_age`). Not tried in this lab.
- **Show who is signed in, prominently, with a *Not you?* link** that ends the IdP session. It turns this ticket into a second of the user's own attention.
- **Tell hot-desk users** to sign out of the identity provider, not only the app, and to use a private window on a PC that isn't theirs.

## Questions I'd ask the customer

1. **What name does it show in the top right** (or wherever the app shows who is signed in)? Is it yours? Can you send a screenshot of the page with the name on it?
2. Is this a computer other people use: shared, hot-desk, a meeting room, a family PC? Who used it before you? Was it a minute ago or yesterday?
3. Did Keycloak (the sign-in page) ask for your username and password, or did it take you straight in?
4. In a **private/incognito window** on the same computer, does it ask for your password and show your name?
5. On another computer, do you sign in as yourself?
6. Did you click **Log out** in the app last time you used it? Did it show a sign-in page afterwards?
7. Did the wrong account's session let you see or change anything you shouldn't have? (Then stop, don't carry on using it, and escalate as a privacy incident.)
