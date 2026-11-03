# Operating the lab

How to use the lab day to day, once it's running. Start with the [Quick start](../README.md#quick-start) in the README.

- [Open the apps: HTTPS only](#open-the-apps-https-only): the URLs, the certificate warning, and why not to trust the lab CA
- [Demo users](#demo-users): who to sign in as, and how to see the password
- [First logins](#first-logins): OIDC, SAML and single sign-on, then one scenario end to end
- [More scenarios to try](#more-scenarios-to-try): break, check and fix commands for a few more
- [How the scenarios work](#how-the-scenarios-work): what each kind of scenario changes, and how it's detected
- [Tests](#tests): what `scripts/test.sh` checks
- [Rotating secrets](#rotating-secrets): when and how
- [Upgrading an existing lab](#upgrading-an-existing-lab): after pulling a new version
- [Troubleshooting](#troubleshooting): `ERR_EMPTY_RESPONSE` and plain `http://` URLs

## Open the apps: HTTPS only

Use a browser on a machine that resolves `LAB_HOST` to the lab host. **Every URL is `https://`.** There is no plain-HTTP listener and no redirect, so `http://` URLs fail with `ERR_EMPTY_RESPONSE` (see [Troubleshooting](#troubleshooting)).

| Service | URL |
|---|---|
| Keycloak (IdP); admin console at `/admin/` | **https://idlab.home:8180** |
| SAML service provider | **https://idlab.home:8181** |
| OIDC relying party | **https://idlab.home:8182** |
| Keycloak through the reverse proxy | **https://idlab.home:8183** |
| SAML service provider through the reverse proxy | **https://idlab.home:8184** |
| OIDC relying party through the reverse proxy | **https://idlab.home:8185** |
| OIDC relying party whose calls to Keycloak go through the egress proxy | **https://idlab.home:8186** |
| OIDC relying party behind the reverse proxy, plain HTTP behind it | **https://idlab.home:8187** |
| API (resource server); called by the OIDC RP on `:8182`, from its server and from the browser | **https://idlab.home:8188** |
| Mutual-TLS route on the reverse proxy; needs a client certificate (curl: see scenarios 18a and 18b) | **https://idlab.home:8189** |

If you set a different `LAB_HOST`, use that instead of `idlab.home`.

Sign in to the apps as one of the [demo users](#demo-users). The Keycloak admin console user is `admin`. To see its password on your own screen, run `grep '^KC_ADMIN_PASSWORD=' .env | cut -d= -f2`.

### The certificate warning is expected

The first time you open each URL, the browser warns *"Your connection is not private"* (`NET::ERR_CERT_AUTHORITY_INVALID` in Chrome and Edge). That's because `setup.sh` created the lab's **own certificate authority**, and your browser has never heard of it. For a lab, it's fine to click **Advanced → Continue/Proceed**.

Accept the warning on each URL you'll use **before** you first log in. Otherwise the hand-off from Keycloak back to an app can stop at a warning page. If that happens, accept it and start the login again. For **Call the API from the browser**, accept it on https://idlab.home:8188/healthz too: until you do, the browser refuses the page's call with a certificate error, which the page reports as `Failed to fetch`, like a CORS refusal. Private/incognito windows ask again.

### Don't install the lab CA as trusted on your computer

You could make the warnings go away by importing `certs/ca.crt` into your operating system's or browser's trusted root store. **Don't**, especially on a machine you use for anything else:

- **The CA is not limited to the lab.** It can sign certificates for *any* hostname: your bank, your email, your company's SSO.
- **Its private key isn't protected like a real CA's.** `certs/ca.key` sits unencrypted on the lab server, readable by anyone who gets that user account, a backup or a copy of the repo directory.
- **Together, that means interception.** Anyone with the key could issue certificates your computer would accept silently, and intercept HTTPS traffic without a single warning. Trusting a root on Windows applies system-wide (Edge, Chrome and other apps), not just to this lab.

Clicking through the warning gives exactly the same lab experience without that risk. The automated tests do trust the CA, but only inside a throwaway browser container that's deleted after each run.

If you imported it earlier, remove it:

- **Windows:** `certmgr.msc` → *Trusted Root Certification Authorities* → *Certificates* → delete **identity-lab Local CA**.
- **macOS:** Keychain Access → delete it from the *System* or *login* keychain.

## Demo users

| User | Email | Lab roles | Use it for |
|---|---|---|---|
| `alice` | alice@idlab.example | `lab-user`, `lab-admin` | The default user: the walkthrough and the automated tests sign in as alice. She has every lab role, so the `role` attribute and `realm_roles` claim are fully populated. |
| `bob` | bob@idlab.example | `lab-user` | An ordinary user. Compare his debug pages with alice's to see how a role difference shows up in the SAML assertion and the ID token. |
| `carol` | carol@idlab.example | *none* | Signed in but not authorised. Logging in succeeds because authentication only proves who she is. The sample apps don't enforce roles, so carol gets in; a real app would check `role` / `realm_roles` and refuse her. |
| `dave` | dave@idlab.example | `lab-user` (LDAP group) | **From LDAP.** The automated tests use dave for the directory logins, the RADIUS logins, and the `ldap-bind-failure` and `radius-shared-secret-mismatch` scenarios. |
| `erin` | erin@idlab.example | `lab-user`, `lab-admin` (LDAP groups) | From LDAP, with every lab role, like alice. |
| `frank` | frank@idlab.example | *none* | From LDAP, in no group, like carol. |

alice, bob and carol live in Keycloak's own database. dave, erin and frank live in the directory under `ou=people,dc=idlab,dc=example`. Keycloak imports each one on their first login, and maps their LDAP groups (`ou=groups`) to the realm roles of the same name. So the claims look the same whichever kind of user signs in. In the admin console, federated users show a *Federation link* to `idlab-ldap`.

Over RADIUS, only the directory users can log in: FreeRADIUS reads the directory, not Keycloak, so alice, bob and carol get Access-Reject from the NAS.

Every user also carries Keycloak's default roles (`default-roles-idlab`, `offline_access`, `uma_authorization`), and these show up in the claims too. In SAML, the `role` attribute also includes the built-in `account` client's roles (`view-profile`, `manage-account`, …). The OIDC `realm_roles` claim has realm roles only.

**Password:** all six share `DEMO_PASSWORD`, which `setup.sh` generates at random into `.env`. It isn't written anywhere else. To see it on your own screen, run this on the lab host:

```bash
grep '^DEMO_PASSWORD=' .env | cut -d= -f2
```

Don't paste it into tickets, chats or screenshots. If it does leak, [rotate the secrets](#rotating-secrets).

## First logins

Start with the lab up, the IdP certificate pinned, and `scripts/status.sh` showing every scenario **healthy**. Use one **normal** browser window for steps 1–3, because single sign-on needs the same browser session. Step 4 uses a private window.

**1. OIDC as alice (≈3 min)**

1. Open **https://idlab.home:8182** and click **Log in with OIDC**.
2. You're sent to Keycloak at `:8180`, realm *Identity Lab*. Sign in as `alice` with the [demo password](#demo-users).
3. You land on **OIDC login succeeded**. Look at:

| Claim | What it tells you |
|---|---|
| `iss` | `https://idlab.home:8180/realms/idlab`, the issuer. The RP rejects tokens from anyone else, so a hostname or realm mismatch here is a classic failure. |
| `aud` / `azp` | `oidc-rp`: the token was issued to *this* client. |
| `sub` | A UUID that never changes for alice. Apps should key users on this, not on email. |
| `email`, `preferred_username`, `realm_roles` | Profile data and authorisation input (alice: `lab-user`, `lab-admin`). |
| `iat` → `exp` | Issued at, and expires 5 minutes later. Compare with "RP clock now". |
| `nonce` | Ties this token to this login attempt, which protects against replay. |
| Header `kid` | Which realm key signed the token. Compare with Keycloak's *Realm settings → Keys*. |

**2. SAML, and single sign-on (≈3 min)**

1. In the **same window**, open **https://idlab.home:8181** and click **Log in with SAML**.
2. This time **there's no password prompt**. The browser bounces through Keycloak and lands straight on **SAML login succeeded**. Keycloak recognised the session from step 1 and issued a SAML assertion to a different app, over a different protocol. That's single sign-on.
3. Look at:

| Field | What it tells you |
|---|---|
| NameID | `alice@idlab.example`, in emailAddress format. This is the SAML subject. |
| Issuer / Audience | The same realm as before, and this SP's entity ID. |
| Signatures | Response **signed**, assertion **signed**. |
| Timing | `NotBefore` → `NotOnOrAfter` is about a 1-minute window. **SP clock − IssueInstant** should be a few seconds at most. |
| Attributes | `email`, `givenName`, `surname`, `role`. |
| IdP signing certificates | The certificate this SP pinned, and whether it's valid. |

**3. Compare (≈1 min)**

It's the same person through two protocols, but the identifiers differ. OIDC `sub` is a UUID; SAML NameID is an email address. Mapping one onto the other is a classic integration mistake. Lifetimes differ too: the ID token lasts 5 minutes, while the SAML assertion must be used within about 1 minute.

**4. Run a scenario end to end (≈3 min)**

1. On the lab host, run `scripts/break.sh clock-skew` and read what it prints.
2. Open a **new private window**, so the sessions from steps 1–2 can't hide anything. Go to **https://idlab.home:8181**, accept the certificate warning again, click **Log in with SAML** and sign in as `alice`.
3. The SP shows **"Could not validate timestamp: expired. Check system clock."** Under *Assertion timing vs SP clock*, `NotOnOrAfter` is about 9 minutes **before** "SP clock now", and **SP clock − IssueInstant** reads **+600 s**.
4. Open [runbook 02](../runbooks/02-clock-skew.md) and follow *Where to look*. For example, `date -u; docker compose exec saml-sp date -u` shows the two clocks 10 minutes apart.
5. Run `scripts/fix.sh clock-skew`. Close the private window, open a new one and log in again. It succeeds, and **SP clock − IssueInstant** is back near 0.

Then try the other scenarios the same way, using `scripts/break.sh` with no argument to list them.

## More scenarios to try

Each block breaks one scenario, shows where the evidence is, and fixes it. `scripts/fix.sh --all` puts everything back.

```bash
scripts/break.sh radius-shared-secret-mismatch
docker compose exec nas nas-auth dave   # nas: no reply from radius:1812 after 3 attempts (6s): RADIUS server not responding
scripts/fix.sh radius-shared-secret-mismatch

scripts/break.sh proxy-rate-limit       # now log in at https://idlab.home:8185: 429 Too Many Requests
docker compose logs proxy | grep 'limiting requests'
scripts/fix.sh proxy-rate-limit

scripts/break.sh proxy-tls-interception # now log in at https://idlab.home:8186: certificate verify failed
docker compose logs squid | grep TLS_LIB_ERR
scripts/fix.sh proxy-tls-interception

scripts/break.sh api-bearer-audience    # log in at https://idlab.home:8182, then "Call the API": 401 invalid_token
docker compose logs api | grep api_token_rejected
scripts/fix.sh api-bearer-audience

scripts/break.sh cors-blocked           # log in at https://idlab.home:8182, then "Call the API from the browser"
docker compose logs api | grep api_request_ok   # a success; the reason it failed is in the browser console (F12)
scripts/fix.sh cors-blocked
```

## How the scenarios work

Every scenario is:

- **reproducible:** driven by scripts, with no manual clicking
- **reversible:** `fix.sh` restores a working state
- **idempotent:** `break` and `fix` read the *live* state first (Keycloak Admin API and its LDAP connection test, container clocks, SP trust store, the NAS's secret, the proxies' settings as their containers see them, the issuer Keycloak reports through the reverse proxy, what the edge app answers through it, the egress app's proxy variables as its process has them, the mTLS client's certificate checked as nginx checks it, and the `Access-Control-Allow-Origin` the API really sends), so running either twice is a no-op

The proxy scenarios change one setting file each in `.state/proxy/` (healthy defaults in `proxy/defaults/`) and reload nginx with `nginx -t && nginx -s reload`, as an admin would. If nginx rejects a change, the previous file is put back. `proxy-gateway-timeout` changes the app behind the proxy instead, through `.state/oidc-rp-proxied/callback-delay`; the proxy keeps its timeout. `redirect-loop` works like the other proxy scenarios, on `.state/proxy/edge-location.conf`, but is detected by what the app answers through the proxy: a redirect to the URL that was asked for.

`proxy-maintenance` is a proxy scenario too, on `.state/proxy/kc-maintenance.conf`, included in the Keycloak locations of the `:8183` server but not in `/nginx-healthz`. The OIDC app behind the proxy fails in one of two ways: if it hasn't cached Keycloak's discovery document since it started, its own back-channel request gets the 503 and it shows `503 Server Error: Service Temporarily Unavailable for url: https://proxy:8183/...`; otherwise the browser gets the maintenance page.

The client-cert scenarios change the client, not the proxy: they remove the partner's certificate and key from `.state/mtls-client/`, or replace them with a lab-CA certificate that expired yesterday. `cors-blocked` changes the API's `.state/api/cors-allow-origin`, which it re-reads on every request.

The API scenarios change Keycloak, not the API, through the Admin REST API like `redirect-uri-mismatch`: the `audience idlab-api` mapper on the `oidc-rp` client, or that client's access token lifespan. Tokens issued before a change keep their old values until they expire, so test with a new login.

The egress proxy scenarios 11 to 13 work the same way on Squid: one include file each in `.state/squid/` (healthy defaults in `squid/defaults/`), applied with `squid -k parse && squid -k reconfigure`. `proxy-bypass` changes the app instead: its `HTTPS_PROXY` and `NO_PROXY` are in `.state/oidc-rp-egress/proxy.env`, and as with any environment variable the container is recreated to pick them up. For 11 to 13 the app fails after the password, at the token request, because it already has Keycloak's discovery document; if it has restarted since its last login, the same error appears straight after **Log in**.

## Tests

```bash
scripts/test.sh            # build, start or reuse the lab, run every check
scripts/test.sh --fresh    # also delete the volumes first (Keycloak database, directory, NAS secret), so everything is re-created
scripts/test.sh --down     # stop the lab afterwards
```

The 282 checks cover:

- container health, the OIDC issuer directly and through the proxy, the apps over TLS verified against the lab CA (directly, through the reverse proxy, and the egress proxy's OIDC app), and an `ldapwhoami` bind as Keycloak's service account over LDAPS
- that the OIDC app behind the egress proxy has no route to Keycloak without it
- that Keycloak ignores X-Forwarded headers sent by anyone but the proxy (a direct request with forged headers still gets the `:8180` issuer)
- that the API answers a call with no token with a bare `WWW-Authenticate: Bearer` challenge, and a malformed token with `error="invalid_token"`, and allows the browser's preflight from the OIDC app's origin
- that the proxy's mutual-TLS route accepts the partner client's certificate, from curl and from Chromium, and refuses a request without one with a 400
- a real Chromium login to each app, directly and through the reverse proxy (including the edge OIDC app it reaches over plain HTTP), and to the OIDC app behind the egress proxy (with its back channel in Squid's log), as a local user (alice) and as an LDAP user (dave)
- the direct OIDC app calling the API with its access token (with the token's `iat` and `exp` in the API's log), its debug page calling the API from the browser (cross-origin, under CORS), and handing out the raw token on `/debug/access-token`
- a RADIUS login from the NAS as dave (Access-Accept), and with a wrong password (Access-Reject)
- for every scenario: break (twice), detected as broken, the exact error in the browser (or in the NAS's output), the matching log line, fix (twice), detected as healthy, and a successful login again
- scenario by scenario, what still works and what else the break leaves behind:
  - `ldap-bind-failure`: alice (a local user) still logs in while LDAP users can't
  - `radius-shared-secret-mismatch`: dave still logs in to the OIDC app while RADIUS is broken
  - every proxy scenario: alice still logs in to the same app directly, bypassing the proxy
  - `proxy-auth-required`: the `egress-svc` account gets through Squid
  - `proxy-tls-interception`: the certificate presented for Keycloak is issued by the inspection CA
  - `redirect-loop`: alice still logs in to the OIDC app through the proxy's other route
  - `api-bearer-audience`: the login itself still works
  - `api-bearer-expired`: a call straight after login still works
  - `proxy-maintenance`: the 503 carries `Retry-After` and the proxy's health check still answers 200
  - the client-cert scenarios: curl gets the same 400 and the proxy's error log gives nginx's reason
  - `cors-blocked`: the server-side API call still works, and the API logged the browser's preflight and its successful `GET`
  - `proxy-bypass`: the fix saved the broken container's log, with its `backchannel_failed` line, before recreating it
- last, that no password or secret from `.env`, authorisation code, OAuth state or other one-time login value (`nonce`, `code_challenge`, `Signature`, `session_code`, `client_data`) appears in any container's log, that the proxy's log has each of those five masked as `***`, no JWT (access or ID token) in any container's log, saved page or `test.log`, and no private key in any container's log or `test.log`

`scripts/test.sh` never writes a secret to `test-results/`: the value of every password and secret from `.env` is replaced with `<redacted>` in its log.

Screenshots, page HTML and a full log go to `test-results/`. [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs the same script on `ubuntu-latest` with `LAB_HOST=localhost`.

## Rotating secrets

```bash
scripts/setup.sh --rotate     # new random value for every secret in .env; certificates untouched
scripts/test.sh --fresh       # recreate the lab with them, then prove it still works
```

`--rotate` replaces `KC_ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, `DEMO_PASSWORD`, `OIDC_CLIENT_SECRET`, `OIDC_PROXIED_CLIENT_SECRET`, `OIDC_EGRESS_CLIENT_SECRET`, `LDAP_ADMIN_PASSWORD`, `LDAP_BIND_PASSWORD`, `RADIUS_LDAP_BIND_PASSWORD`, `RADIUS_SECRET`, `EGRESS_PROXY_PASSWORD` and the two apps' session keys. It prints none of them.

The second step matters. Postgres, the Keycloak admin account, the demo users, the OIDC client secrets and the directory's passwords only receive their values when the databases are first created, and the NAS stores its copy of the RADIUS secret when its volume is first created. `--fresh` deletes the Keycloak, LDAP and NAS volumes, re-imports the realm, re-seeds the directory and the NAS. That also discards anything you changed by hand in the admin console. Afterwards, look up the new demo password with `grep '^DEMO_PASSWORD=' .env | cut -d= -f2`. Existing browser sessions will no longer work, so sign in again.

When you'd do it:

- **A secret has been seen** somewhere it shouldn't be: a screen share or recording, a screenshot, a chat or support ticket, a terminal transcript, a log, or an AI assistant session.
- **`.env` has left the machine**: copied to another host, a backup or a laptop.
- **Someone no longer needs access**: they had the admin or demo password and shouldn't keep it.
- **Before a demo or handing the lab to someone else**, and periodically as good hygiene.

If a **private key** may have been exposed, especially `certs/ca.key`, rotating `.env` isn't enough. Run `scripts/setup.sh --force` to regenerate the CA, TLS and signing keys as well as the secrets, then `scripts/test.sh --fresh`. Remove the old CA from anywhere you trusted it.

## Upgrading an existing lab

After pulling a new version, run:

```bash
scripts/setup.sh          # adds any new secrets, certificates and settings; keeps your existing secrets
scripts/test.sh --fresh   # rebuilds the lab from the repository and .env, and proves it works
```

`--fresh` deletes the lab's volumes: the Keycloak database (with anything you changed in the admin console), the LDAP directory and the NAS's copy of the RADIUS secret. They're re-created from the realm import, the seed LDIF and `.env`. Your `.env`, `certs/` and `.state/` are kept. [CHANGELOG.md](../CHANGELOG.md) lists what each phase added and why it needs these steps.

## Troubleshooting

### `ERR_EMPTY_RESPONSE`: "This page isn't working · idlab.home didn't send any data"

**Cause:** you opened an `http://` URL, such as `http://idlab.home:8181`. The lab's ports speak only TLS. When a plain-HTTP request arrives on a TLS port, the server can't parse it and closes the connection without replying. There's no HTTP listener to redirect you to HTTPS. Browsers often autocomplete the `http://` version once you've typed it.

**Fix:** type the full `https://` URL, for example `https://idlab.home:8181/`. If the address bar keeps suggesting the `http://` one, highlight that suggestion and press **Shift+Delete** (Chrome or Edge) to remove it.

**Check from the lab host:**

```bash
curl -sS http://localhost:8181/                                  # curl: (52) Empty reply from server
curl -sS --cacert certs/ca.crt https://localhost:8181/healthz    # {"status":"ok"}
```
