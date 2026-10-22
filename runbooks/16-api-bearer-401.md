# 16 · API: 401 with a Bearer token (wrong audience, expired token)

| | |
|---|---|
| **Protocol** | OAuth 2.0 bearer tokens (RFC 6750). An app gets an access token from Keycloak at login and sends it to an API in `Authorization: Bearer <token>`. The API (the *resource server*) checks the token itself: the signature against Keycloak's published keys (JWKS), the issuer (`iss`), the expiry (`exp`) and that the token is meant for it (`aud`). When a check fails, it answers **401** with a `WWW-Authenticate: Bearer` header saying why. |
| **Blast radius** | Every call from the one client whose tokens are wrong, to every API that checks them. The login itself works, and so does everything that only needs the ID token, which is why it gets reported as "the API is down". Other clients' tokens are fine. |
| **Typical trigger** | **Audience:** client settings copied between environments (the audience mapper or requested resource names another API); an API given a new identifier; a new client created without the audience; tokens for one API reused for another. **Expiry:** an access token lifespan shortened in the IdP (hardening, a typo, minutes taken as seconds); an app that keeps the token from login and never refreshes it; a long-running job or a tab left open; clock skew between IdP and API (runbook 02). |
| **Lab** | Two scenarios, one runbook. `scripts/break.sh api-bearer-audience` · `scripts/fix.sh api-bearer-audience` (changes the `audience idlab-api` mapper on Keycloak's `oidc-rp` client to `idlab-api-staging`). `scripts/break.sh api-bearer-expired` · `scripts/fix.sh api-bearer-expired` (sets the `oidc-rp` client's access token lifespan to 10 seconds). The API isn't touched in either. |

## Symptom

Go to https://LAB_HOST:8182/, click **Log in with OIDC** and sign in. The login works and the debug page shows **OIDC login succeeded**. Under **API**, click **Call the API**.

**Wrong audience** (`api-bearer-audience`), every time:

```
API call failed: 401 UNAUTHORIZED
WWW-Authenticate   Bearer realm="idlab-api", error="invalid_token", error_description="The access token audience (idlab-api-staging account) does not include idlab-api"
{"error":"invalid_token","error_description":"The access token audience (idlab-api-staging account) does not include idlab-api"}
```

**Expired token** (`api-bearer-expired`): a click straight after login works. A click more than 10 seconds after login fails:

```
API call failed: 401 UNAUTHORIZED
WWW-Authenticate   Bearer realm="idlab-api", error="invalid_token", error_description="The access token expired at 2026-10-22T08:53:59Z"
```

and keeps failing until you log in again, because this app never refreshes its token.

The API's log, one line per rejected call, with the claims that decided it (never the token):

```
2026-10-22 08:51:43,568 WARNING api event=api_token_rejected error=invalid_token error_description='The access token audience (idlab-api-staging account) does not include idlab-api' sub=e52e5f3f-8b98-4f7d-935e-3fa7bbacb59f azp=oidc-rp aud='idlab-api-staging account' iss=https://idlab.home:8180/realms/idlab iat=2026-10-22T08:51:43Z exp=2026-10-22T08:56:43Z
2026-10-22 08:52:31,575 WARNING api event=api_token_rejected error=invalid_token error_description='The access token expired at 2026-10-22T08:52:26Z' sub=e52e5f3f-8b98-4f7d-935e-3fa7bbacb59f azp=oidc-rp aud='idlab-api account' iss=https://idlab.home:8180/realms/idlab iat=2026-10-22T08:52:16Z exp=2026-10-22T08:52:26Z
```

and the app's log, for each call:

```
2026-10-22 08:51:43,569 INFO oidc-rp event=api_call url=https://api:8188/v1/whoami status=401 www_authenticate='Bearer realm="idlab-api", error="invalid_token", error_description="The access token audience (idlab-api-staging account) does not include idlab-api"'
```

Keycloak logs nothing: as far as it's concerned, it issued a token and the login succeeded.

How customers describe it: *"login works but the app can't load any data"*, *"the API says 401 even though I'm logged in"*, or, for expiry, *"it works for a few minutes after login, then everything fails until I log in again"*.

Not every API is this helpful. Many answer a bare `401` with `WWW-Authenticate: Bearer` and no `error_description`, or don't send the header at all. Then the token itself is the only evidence, which is where token-inspector comes in.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  api-bearer-audience            broken   oidc-rp access tokens get aud idlab-api-staging, the API expects idlab-api
#  api-bearer-expired             broken   oidc-rp access.token.lifespan=10s, shorter than the RP keeps using its token

# What the API said, and why
docker compose logs --since 10m api | grep api_token_rejected
docker compose logs --since 10m oidc-rp | grep event=api_call

# The audience mapper and lifespan on the client, as Keycloak has them
# (Clients > oidc-rp > Client scopes > oidc-rp-dedicated, and Advanced > Access Token Lifespan in the admin console)
```

The API's own error decides it here. When it doesn't say enough, check the token.

### Check the token with token-inspector

[token-inspector](https://github.com/MarkHawk/token-inspector) decodes a JWT and checks it offline, against the issuer's keys and the values the API expects. It never contacts the issuer, so it's safe on a support laptop.

**An access token is a live credential until it expires.** Anyone who has it can call the API as the user. So:

- Keep it in a file only you can read (`umask 077`), not in a ticket, chat or shell history. Don't paste it after `--token` on the command line, where `ps` and your history can see it.
- Use `--redact` for any report you paste back into a ticket.
- Delete the files when you're done. A customer should send the token only through a channel your team approves for credentials, and only after it has expired if the check allows it.

In the lab, get the token from the app while you're logged in: on the debug page, the link **show the raw token** (`/debug/access-token`) returns it as plain text. That stands in for copying it from the `Authorization` header in the browser's developer tools, or from a HAR file (which token-inspector reads directly). The app shows it only on that request: no page embeds it, and nothing logs it.

```bash
umask 077
mkdir -p ~/ticket-1234 && cd ~/ticket-1234
# Save the token from https://LAB_HOST:8182/debug/access-token as access-token.txt (same browser session).
# Keycloak's public signing keys (not secret):
curl -sS --cacert ~/identity-lab/certs/ca.crt https://LAB_HOST:8180/realms/idlab/protocol/openid-connect/certs > jwks.json

# Replay the API call with that token. curl reads the header from a file, so the token stays off the command line.
printf 'Authorization: Bearer %s\n' "$(cat access-token.txt)" > auth-header.txt
curl -sS -i --cacert ~/identity-lab/certs/ca.crt -H @auth-header.txt https://LAB_HOST:8188/v1/whoami

cd ~/token-inspector
token-inspector ~/ticket-1234/access-token.txt --token-type access \
  --jwks ~/ticket-1234/jwks.json \
  --expect-issuer https://idlab.home:8180/realms/idlab --expect-audience idlab-api \
  --redact
```

`--token-type access` stops it guessing (ID token checks such as the nonce don't apply). `--expect-audience` and `--expect-issuer` are what the API expects. Without them, those checks show as SKIP.

**Wrong audience**, checked as at the moment it was captured (`--now 2026-10-22T08:53:36Z`). Trimmed to the parts that matter:

```
== Claims ==
  exp                 2026-10-22 08:58:26 UTC (in 5 min)
  iat                 2026-10-22 08:53:26 UTC (10 s ago)
  iss                 https://idlab.home:8180/realms/idlab
  aud                 ["idlab-api-staging", "account"]
  sub                 e***
  typ                 Bearer
  azp                 oidc-rp
  scope               openid email profile

== Checks ==
  PASS  Signature               Valid RS256 signature, verified with key
                                'ftWLDaSRtHG344k96uSBv5zS6uUvgb4dRSEcXE02U6s' from JWKS jwks.json.
  PASS  Expiry (exp)            Valid for another 5 min (exp 2026-10-22 08:58:26 UTC).
  PASS  Issuer (iss)            Matches 'https://idlab.home:8180/realms/idlab'.
  FAIL  Audience (aud)          The audience is 'idlab-api-staging', 'account', but 'idlab-api' was
                                expected.
                                Next: The token was issued for a different client or API. Check the
                                      client ID the relying party is configured with, and for access
                                      tokens the audience (resource) requested from the IdP.

== Likely cause ==
  The token was issued to a different client or API than the one checking it, so its aud or azp does
  not name this relying party.
  First:     Check that the client ID the application logs in with is the one it validates tokens
             against, and that the token was not taken from another application.
  Explains:  Audience (aud)

Verdict: 1 problem to fix (1 FAIL, 0 WARN, 6 PASS, 4 SKIP)
```

Signature, issuer and expiry are fine, so the token is genuine and current. Only `aud` is wrong, and `azp: oidc-rp` says which client it was issued to: that's the client whose settings to look at. (`account` is Keycloak's own: it adds it for the user's account-console roles, and it's harmless.)

**Expired token**, checked 5 seconds after `exp`:

```
== Claims ==
  exp                 2026-10-22 08:53:59 UTC (5 s ago)
  iat                 2026-10-22 08:53:49 UTC (15 s ago)

== Checks ==
  WARN  Expiry (exp)            Expired 5 s ago, but that is inside the 60 s skew allowance.
                                Next: A receiver with a stricter allowance will reject it. Check
                                      both clocks use NTP.
                                Runbook: identity-lab 02-clock-skew
  PASS  Audience (aud)          Matches 'idlab-api'.

Verdict: no failures, 1 warning to review (0 FAIL, 1 WARN, 6 PASS, 4 SKIP)
```

Two things to know when reading this:

1. **Match token-inspector's skew allowance to the API's.** token-inspector allows 60 seconds by default. This API allows none, so the same token the API rejected only gets a WARN. Add `--skew 0` (or whatever the API allows) and the expiry check fails as it did at the API.
2. **The likely cause it gives is clock skew, and here that's wrong.** With `--skew 0`, or checked a few minutes later, it says *"The clocks on the IdP and the receiving server most likely disagree"* and points at runbook 02. From the token alone, a token that expired a little before it was used looks the same either way. Tell them apart with two facts:
   - **The token's lifetime:** `exp - iat` is **10 seconds** here. Keycloak's default is 300 (5 minutes), and most IdPs issue 5 to 60 minutes. A lifetime that short is a setting, not a clock.
   - **The clocks:** compare the IdP's and the API's clocks with UTC (`docker compose exec keycloak date -u` and `docker compose exec api date -u` agree here). With clock skew, the token would fail even straight after login. Here a call straight after login works.

## Diagnosis

1. **Read the `WWW-Authenticate` header first.** RFC 6750 defines three error codes: `invalid_request` (malformed request, 400), `invalid_token` (expired, revoked, malformed or for someone else, 401) and `insufficient_scope` (valid token, missing scope, 403). A bare `Bearer realm="..."` with no error means no token arrived at all: look for a proxy or gateway stripping the `Authorization` header, or an app not sending it.
2. **Is the token genuine and current?** Signature, `iss` and `exp`. A bad signature with an unknown `kid` means the API has stale keys after Keycloak rotated them. A different `iss` (scheme, host, port or realm) means the token came through another route to the IdP (runbook 09) or from another realm or environment.
3. **Is it meant for this API?** `aud` must contain the API's identifier, exactly. In Keycloak, access tokens get an audience from an **audience mapper** (on the client, or in a client scope assigned to it) or from client roles of the API's client. Without one, Keycloak access tokens often carry only `account`. `azp` names the client the token was issued to. That's the client to look at, not the API.
4. **Why it isn't the login.** The ID token and the access token are separate. The login only checks the ID token, whose `aud` is the client ID, so it keeps working. Only the calls that send the access token fail.
5. **Expired: a short lifetime, an app that doesn't refresh, or a clock.** Look at `exp - iat` (the lifetime the IdP gave it; the API logs both, on every line), the time of the failing call (in the API's log), and whether a call straight after login works. Here the lifetime is 10 seconds, the app never refreshes, and a call within 10 seconds of login works. The same app with the normal 5-minute tokens fails the same way, five minutes after login: that's the bug the shorter lifespan exposed.

**Root cause, in one sentence for the customer:**
- *Audience:* the IdP's settings for this app were changed to issue access tokens for a different API (`idlab-api-staging`), so the API rejects them as not meant for it; logins still work because they don't use the access token.
- *Expiry:* the access token lifetime for this app was cut to 10 seconds, and the app keeps using the token it got at login instead of refreshing it, so every API call made more than 10 seconds after login is rejected as expired.

## Fix

**Wrong audience.**

1. Make the client's tokens name the API again. In the lab:
   ```bash
   scripts/fix.sh api-bearer-audience
   ```
   By hand, in the admin console: **Clients > oidc-rp > Client scopes > oidc-rp-dedicated**, open the mapper **audience idlab-api**, set **Included Custom Audience** to `idlab-api` and save. Tokens issued before the change keep their old `aud` until they expire. Log in again to get a new one.
2. Verify: **Call the API** after a new login shows **API call succeeded: 200 OK**, the decoded access token on the debug page shows `aud` with `idlab-api`, and `scripts/status.sh` shows `healthy`.

Don't fix it by making the API accept any audience, or the staging one. The audience check is what stops a token issued for one service from being replayed against another.

**Expired token.**

1. In the lab, put the lifespan back:
   ```bash
   scripts/fix.sh api-bearer-expired
   ```
   By hand: **Clients > oidc-rp > Advanced > Access Token Lifespan**, back to *Inherits from realm settings*.
2. The real fix is in the app: **refresh the access token before it expires** (use the refresh token, or the library's automatic refresh, when `exp` is near or the API answers `invalid_token`), rather than keeping one token for the whole session. Otherwise the same failure comes back five minutes after login with the normal lifespan.
3. Verify: **Call the API** more than 10 seconds after a new login works, and `scripts/status.sh` shows `healthy`.

Don't fix it by making access tokens last for hours. A stolen access token can't be revoked at most APIs, which check it offline as this one does. Short lifetimes and refreshing are the point.

## Prevention

- **Treat the audience as part of the API's contract.** Record each API's identifier and which clients may call it, and check the access token's `aud` (not just a successful login) after any client change, export or import.
- **Promote client settings between environments with per-environment values** (audiences, URLs), not copied exports.
- **Refresh tokens in every client** and test it: a synthetic check that calls the API more than one token lifetime after login catches an app that never refreshes.
- **Change token lifespans deliberately,** and tell app owners first: a shorter lifespan exposes every app that doesn't refresh.
- **Make APIs say why.** An `error_description` in `WWW-Authenticate` and one log line with the deciding claims (never the token) turn this into a five-minute ticket.

## Questions I'd ask the customer

1. What exactly does the API return: the status, the full `WWW-Authenticate` header, the body? Does the login itself work?
2. Does it fail on the first call after login, or only after some time? How long?
3. Which client (`azp`) is the token from, and what `aud`, `iss`, `iat` and `exp` does it carry? (A redacted token-inspector report is enough; please don't send a live token.)
4. What audience and issuer is the API configured to accept, and what clock-skew allowance does it use?
5. What changed recently: client settings, an import or export, token lifespans, the API's identifier, a gateway in front of the API?
6. Does the app refresh its access tokens? With which library, and when?
