# 03 · Redirect URI mismatch (OIDC)

| | |
|---|---|
| **Protocol** | OpenID Connect, authorization code flow |
| **Blast radius** | Every login to the affected client. Users never reach the login form. |
| **Typical trigger** | The app moved (new hostname, port, path, `http`→`https`, added `/auth` prefix or trailing slash), or someone edited the client registration on the IdP. |
| **Lab** | `scripts/break.sh redirect-uri-mismatch` · `scripts/fix.sh redirect-uri-mismatch` (changes the registered URI to `/callback` while the app keeps sending `/auth/callback`) |

## Symptom

The user clicks **Log in** and lands on a Keycloak error page **before any login form appears**:

```
We are sorry...
Invalid parameter: redirect_uri
« Back to Application
```

Other IdPs word it as `AADSTS50011: The redirect URI ... does not match the redirect URIs configured for the application` (Entra ID), `redirect_uri_mismatch` (Google), or "The 'redirect_uri' parameter must be a Login redirect URI in the client app settings" (Okta).

How customers describe it: *"We moved the app to a new URL and now SSO shows an error page,"* or *"Login broke after someone tidied up the IdP config."*

## Where to look

Run from the repository root on the lab host.

```bash
# IdP: the rejected request, including the redirect_uri the app actually sent
docker compose logs keycloak | grep invalid_redirect_uri
#  WARN [org.keycloak.events] (executor-thread-20) type="LOGIN_ERROR", realmName="idlab",
#       clientId="oidc-rp", userId="null", ipAddress="172.18.0.1",
#       error="invalid_redirect_uri", redirect_uri="https://idlab.home:8182/auth/callback"

# App: what it is configured to send
docker compose logs oidc-rp | grep oidc_authorize_redirect
#  INFO oidc-rp event=oidc_authorize_redirect redirect_uri=https://idlab.home:8182/auth/callback

# IdP: what is registered for the client
bash -c 'source scripts/lib.sh; load_env; kc_api GET "/idlab/clients?clientId=oidc-rp" | jq ".[0].redirectUris"'
#  [ "https://idlab.home:8182/callback" ]        <- broken state

scripts/status.sh   # redirect-uri-mismatch  broken  redirectUris=https://idlab.home:8182/callback (app sends .../auth/callback)
```

In the admin console, go to **Clients → oidc-rp → Settings → Valid redirect URIs**.

The app's own log has **no** `oidc_login_failed` line. The browser never returns to the app, so from the app's point of view the user simply never came back. This is a common reason customers say "there's nothing in our logs".

## Diagnosis

1. **The error appears before any login form.** The IdP rejected the authorization request itself, so this is not a credentials or user problem.
2. **Put the two values side by side:** the `redirect_uri` in the IdP's `LOGIN_ERROR` event (or in the browser's address bar on the error page), and the client's registered *Valid redirect URIs*.
3. **Compare character by character.** Keycloak matches exactly, except for an explicit trailing `*` wildcard. Usual culprits:
   - scheme (`http` vs `https`)
   - host (`app` vs `app.example.com`, a load balancer host vs the internal host)
   - port (`:443` written out vs left implicit)
   - path (`/callback` vs `/auth/callback`)
   - trailing slash
   - case
4. **Check for a proxy in front of the app.** If the URI the app sends is wrong (for example `http://` behind a TLS-terminating proxy), the app is building it from the wrong scheme or host. In that case fix the app's proxy settings, not the IdP.

**Root cause, in one sentence for the customer:** the application sends `https://idlab.home:8182/auth/callback` as its redirect URI, but the IdP client only allows `https://idlab.home:8182/callback`, so the IdP refuses to start the login.

## Fix

Make the registered URI match the one the app really uses. Decide which side is "right" first.

- **The IdP registration is wrong** (the case in the lab): add the exact URI to *Valid redirect URIs*.
  ```bash
  scripts/fix.sh redirect-uri-mismatch
  ```
- **The app is building the wrong URI**, for example behind a proxy: fix the app's base URL or forwarded-headers settings. Don't register an incorrect URI to match it.

Avoid broad wildcards such as `https://*` or `/*` as a quick fix. A loose redirect URI lets an attacker have authorization codes delivered to a URL they control.

Verify with a fresh login in a private window. The login form should appear, and the `/debug` page should show the ID token.

## Prevention

- Manage client registrations as code (realm export or Terraform) and review changes. A diff showing `redirectUris` changed would have caught this.
- Include the redirect URI change in the app's release or migration checklist, and register the new URI **before** cutting over, keeping both during the transition.
- Use exact URIs per environment rather than wildcards.
- Run a synthetic login check after IdP or app deploys (this lab's `scripts/test.sh` does exactly that).

## Questions I'd ask the customer

1. Does the error appear before or after you enter your password? (Before means the authorization request itself was rejected.)
2. Can you send the full URL from the browser address bar on the error page? (It contains the `redirect_uri` the app sent.)
3. Has the application's URL, port, path or proxy/load balancer setup changed recently?
4. Has anyone changed the client or app registration on the IdP? Is there an audit log entry?
5. Which environment is affected: production, staging, or both? Do they share one client registration?
6. Is the app behind a reverse proxy that terminates TLS, and does the app know its public URL?
