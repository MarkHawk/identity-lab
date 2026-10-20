# identity-lab

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/MarkHawk/identity-lab?quickstart=1)

A self-contained identity lab you can break on purpose. A Keycloak identity provider, an OpenLDAP directory it federates users from, two sample apps (one SAML, one OIDC), and a FreeRADIUS server with a NAS that authenticates the same directory users, all run in Docker Compose. One-command scenarios reproduce real single sign-on and network login failures, and each scenario has a support-style runbook for diagnosing and fixing it.

## The problem this solves

When enterprise SSO breaks, the support engineer usually sees only the customer's description: *"SSO stopped working for everyone"*. The cause is buried in signed XML, token claims, certificates, clocks and two sets of logs owned by different teams.

This lab makes those failures **reproducible and safe to practise on**:

- **Break it:** `scripts/break.sh <scenario>` puts the lab into a realistic failure, such as an expired IdP certificate, a skewed clock, a mismatched redirect URI, a failing LDAP bind or a RADIUS shared secret mismatch.
- **See it as the customer does:** the apps show the exact error a user would see. Their debug pages show the decoded SAML assertion or ID token. The NAS shows what a switch or VPN gateway would: Access-Accept, Access-Reject or no reply.
- **Diagnose it as support would:** every scenario has a runbook covering the symptom, where to look, diagnosis, fix, prevention, and the questions to ask the customer.
- **Prove it:** `scripts/test.sh` runs a real headless-browser login against each app and a RADIUS login from the NAS, breaks every scenario, asserts the user-facing error and the log evidence, fixes it, and asserts recovery. CI runs the same script.

## Architecture

```mermaid
flowchart LR
    user(["Browser<br/>(you, or Playwright in tests)"])

    subgraph host["Docker host · LAB_HOST (idlab.home / localhost)"]
        direction LR
        kc["Keycloak 26.7<br/>realm idlab<br/>:8180 HTTPS"]
        pg[("Postgres 17<br/>Keycloak DB")]
        ldap[("OpenLDAP 2.6<br/>dc=idlab,dc=example<br/>ldaps://ldap:1636<br/>internal only")]
        sp["SAML SP<br/>Flask + python3-saml<br/>:8181 HTTPS<br/>libfaketime"]
        rp["OIDC RP<br/>Flask + Authlib<br/>:8182 HTTPS"]
        pin[/".state/saml-sp/<br/>pinned IdP cert<br/>faketime offset"/]
        subgraph radnet["internal network radius · 172.30.181.0/24"]
            nas["NAS (RADIUS client)<br/>radclient · 172.30.181.10<br/>own copy of the shared secret"]
        end
        radius["FreeRADIUS 3.2<br/>UDP 1812/1813<br/>internal only"]
    end

    user -- "AuthnRequest / login form" --> kc
    user -- "SAMLResponse (POST)" --> sp
    user -- "code + state (redirect)" --> rp
    rp -- "back channel: discovery, token,<br/>userinfo, JWKS · https://keycloak:8180" --> kc
    kc --- pg
    kc -- "LDAPS: bind as keycloak-svc,<br/>search users and groups,<br/>bind as the user" --> ldap
    pin -. "read on every login" .-> sp
    nas -- "Access-Request (PAP)<br/>+ Message-Authenticator,<br/>shared secret" --> radius
    radius -- "LDAPS: bind as radius-svc,<br/>search the user,<br/>bind as the user" --> ldap
    scripts["scripts/break.sh · fix.sh · status.sh"] -- "Admin REST API" --> kc
    scripts -- "pin cert, set clock offset" --> pin
    scripts -- "set the NAS's secret<br/>(docker compose exec)" --> nas
```

- **Front channel:** browsers reach everything at `https://$LAB_HOST:818x`. Keycloak issues tokens with that issuer.
- **Back channel:** the OIDC RP talks to Keycloak directly over the compose network at `https://keycloak:8180`, rewriting the token, userinfo and JWKS endpoints from discovery to that address (`OIDC_BACKCHANNEL_BASE`). The same images therefore work with `LAB_HOST=idlab.home` on a LAN and `LAB_HOST=localhost` in CI.
- **Directory:** Keycloak federates users from OpenLDAP (read only, imported on first login). It binds as a dedicated read-only service account, `cn=keycloak-svc`, to find users and their groups, then binds as the user to check the password. The directory has no host port; it's reachable only on the compose network.
- **RADIUS:** the NAS stands in for a switch, wireless controller or VPN gateway. It sends PAP Access-Requests to FreeRADIUS, which finds the user in the directory as its own read-only account, `cn=radius-svc`, and checks the password by binding as the user. So dave, erin and frank can log in over RADIUS as well as through Keycloak. RADIUS publishes no host port. The NAS sits on an internal network with a fixed IP, because the server identifies clients by source address.
- **SP trust:** the SAML SP doesn't fetch IdP metadata. Like most SaaS service providers, it trusts the IdP certificate pinned at onboarding (`scripts/pin-idp-cert.sh`).

## Quick start

**Prerequisites:** Linux with Docker Engine and Compose v2, plus `bash`, `openssl`, `curl` and `jq`. It uses host ports 8180–8182.

```bash
git clone <this repo> identity-lab && cd identity-lab

scripts/setup.sh                 # CA, certificates and random secrets -> .env and certs/ (prints no secrets)
                                 # set LAB_HOST=localhost first if you have no DNS name for this machine
docker compose up -d --wait      # Keycloak + Postgres + OpenLDAP + FreeRADIUS + NAS + both apps (first build takes a few minutes)
scripts/pin-idp-cert.sh          # "onboard" the SAML SP: trust the IdP's current signing certificate
scripts/status.sh                # service health and the live state of every scenario
docker compose exec nas nas-auth dave   # a RADIUS login from the NAS; enter the demo password -> "nas: Access-Accept"
```

**Upgrading a lab from before the LDAP directory or RADIUS was added?** Run `scripts/setup.sh` (it adds the new secrets and certificate to your existing `.env` and `certs/`), then `scripts/test.sh --fresh`. The LDAP federation is created at realm import, which only happens when the Keycloak database is new, and the directory's `radius-svc` account is created when the directory is first seeded. `--fresh` deletes the Keycloak, LDAP and NAS volumes.

### Open the apps: HTTPS only

Use a browser on a machine that resolves `LAB_HOST` to the lab host. **Every URL is `https://`.** There is no plain-HTTP listener and no redirect, so `http://` URLs fail with `ERR_EMPTY_RESPONSE` (see [Troubleshooting](#troubleshooting)).

| Service | URL |
|---|---|
| Keycloak (IdP); admin console at `/admin/` | **https://idlab.home:8180** |
| SAML service provider | **https://idlab.home:8181** |
| OIDC relying party | **https://idlab.home:8182** |

If you set a different `LAB_HOST`, use that instead of `idlab.home`.

Sign in to the apps as one of the [demo users](#demo-users). The Keycloak admin console user is `admin`. To see its password on your own screen, run `grep '^KC_ADMIN_PASSWORD=' .env | cut -d= -f2`.

#### The certificate warning is expected

The first time you open each URL, the browser warns *"Your connection is not private"* (`NET::ERR_CERT_AUTHORITY_INVALID` in Chrome and Edge). That's because `setup.sh` created the lab's **own certificate authority**, and your browser has never heard of it. For a lab, it's fine to click **Advanced → Continue/Proceed**.

Accept the warning on all three URLs **before** you first log in. Otherwise the hand-off from Keycloak back to an app can stop at a warning page. If that happens, accept it and start the login again. Private/incognito windows ask again.

#### Don't install the lab CA as trusted on your computer

You could make the warnings go away by importing `certs/ca.crt` into your operating system's or browser's trusted root store. **Don't**, especially on a machine you use for anything else:

- **The CA is not limited to the lab.** It can sign certificates for *any* hostname: your bank, your email, your company's SSO.
- **Its private key isn't protected like a real CA's.** `certs/ca.key` sits unencrypted on the lab server, readable by anyone who gets that user account, a backup or a copy of the repo directory.
- **Together, that means interception.** Anyone with the key could issue certificates your computer would accept silently, and intercept HTTPS traffic without a single warning. Trusting a root on Windows applies system-wide (Edge, Chrome and other apps), not just to this lab.

Clicking through the warning gives exactly the same lab experience without that risk. The automated tests do trust the CA, but only inside a throwaway browser container that's deleted after each run.

If you imported it earlier, remove it:

- **Windows:** `certmgr.msc` → *Trusted Root Certification Authorities* → *Certificates* → delete **identity-lab Local CA**.
- **macOS:** Keychain Access → delete it from the *System* or *login* keychain.

### Demo users

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

### Break something

```bash
scripts/break.sh clock-skew      # now try the SAML login
scripts/status.sh                # clock-skew  broken  saml-sp clock is +600s vs host ...
scripts/fix.sh clock-skew        # or: scripts/fix.sh --all

scripts/break.sh radius-shared-secret-mismatch
docker compose exec nas nas-auth dave   # nas: no reply from radius:1812 after 3 attempts (6s): RADIUS server not responding
scripts/fix.sh radius-shared-secret-mismatch
```

## Run it in Codespaces

No local setup: GitHub Codespaces runs the whole lab in a cloud container you drive from your browser. New to Codespaces? Follow the [step-by-step guide](docs/codespaces.md).

1. Click **Open in GitHub Codespaces** at the top of this page, then **Create codespace**. It picks a **2-core, 8 GB** machine, the smallest size: the whole lab uses about 1 GB once running and peaked at 1.7 GB while building and testing.
2. Wait for the terminal to show `setup complete for https://localhost:8180`. Creating the codespace takes a few minutes; `scripts/setup.sh` itself takes a few seconds. Secrets and certificates are generated inside your codespace and never committed.
3. In the terminal, build the lab and prove it works. The first run takes about 8 to 10 minutes because it builds every image, including a Chromium test image:

   ```bash
   scripts/test.sh --fresh
   ```

4. Try a scenario:

   ```bash
   scripts/break.sh radius-shared-secret-mismatch
   docker compose exec nas nas-auth dave   # paste the demo password: grep '^DEMO_PASSWORD=' .env | cut -d= -f2
   scripts/status.sh                       # radius-shared-secret-mismatch  broken
   scripts/fix.sh radius-shared-secret-mismatch
   ```

   Any scenario from the [table](#scenarios) works the same way, and `scripts/test.sh` checks each one's browser error and log evidence for you.

**Browser logins aren't supported in the codespace's own forwarded URLs.** The Ports tab lists 8180 (Keycloak), 8181 (SAML SP) and 8182 (OIDC RP), but Codespaces gives each port its own hostname, `https://<codespace>-8181.app.github.dev` with no port number. The lab's issuer, SAML entity IDs and redirect URIs are all `https://LAB_HOST:<port>` (in a codespace, `https://localhost:8181` and so on), so a login started there is sent back to `localhost` and fails. Making the lab follow per-port hostnames would mean a different URL scheme from the one you'd see locally and in CI, so it doesn't. Use desktop VS Code (below) to log in yourself, or `scripts/test.sh`: it runs real Chromium logins inside the codespace and saves screenshots and page HTML to `test-results/`.

**Clicking through the apps yourself: open the codespace in desktop VS Code.** With the GitHub Codespaces extension installed, use [github.com/codespaces](https://github.com/codespaces) > **...** > **Open in** > **Visual Studio Code**. VS Code forwards ports 8180 to 8182 to your own `localhost` on the same numbers, so `https://localhost:8181/` and the other [lab URLs](#open-the-apps-https-only), with `localhost` in place of `idlab.home`, work in your own browser. [docs/codespaces.md](docs/codespaces.md) is a step-by-step guide for first-time Codespaces users.

**Codespaces uses your own GitHub allowance.** Personal accounts get a free monthly quota of core hours and storage; a 2-core machine uses two core hours for every hour it runs. Stop the codespace when you're done (it also stops itself when idle), and delete it from [github.com/codespaces](https://github.com/codespaces) to free its storage. See GitHub's [Codespaces billing documentation](https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-codespaces/about-billing-for-github-codespaces) for the current quotas.

## Try it in 10 minutes

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
4. Open [runbook 02](runbooks/02-clock-skew.md) and follow *Where to look*. For example, `date -u; docker compose exec saml-sp date -u` shows the two clocks 10 minutes apart.
5. Run `scripts/fix.sh clock-skew`. Close the private window, open a new one and log in again. It succeeds, and **SP clock − IssueInstant** is back near 0.

Then try the other scenarios the same way, using `scripts/break.sh` with no argument to list them.

## Scenarios

| # | Scenario | App | What breaks | What the user sees | Runbook |
|---|---|---|---|---|---|
| 1 | `expired-signing-cert` | SAML | The IdP signing certificate pinned on the SP passes its `notAfter` date | `IdP signing certificate expired on <date>; the SP has no valid IdP certificate pinned` | [01-expired-signing-cert](runbooks/01-expired-signing-cert.md) |
| 2 | `clock-skew` | SAML | The SP's clock runs 10 minutes fast (libfaketime in the SP container only) | `Could not validate timestamp: expired. Check system clock.` | [02-clock-skew](runbooks/02-clock-skew.md) |
| 3 | `redirect-uri-mismatch` | OIDC | The client's registered redirect URI no longer matches what the app sends | Keycloak: `We are sorry... Invalid parameter: redirect_uri` | [03-redirect-uri-mismatch](runbooks/03-redirect-uri-mismatch.md) |
| 4 | `ldap-bind-failure` | Both (tested on OIDC) | Keycloak's stored LDAP bind password no longer matches the service account, so the directory returns result 49, invalid credentials. Only LDAP users are affected; alice still logs in. | Keycloak (as dave): `Unexpected error when handling authentication request to identity provider.` A directory user who has never logged in gets `Invalid username or password.` | [04-ldap-bind-failure](runbooks/04-ldap-bind-failure.md) |
| 5 | `radius-shared-secret-mismatch` | RADIUS (NAS) | The NAS's copy of the RADIUS shared secret no longer matches the server's client entry, so the server can't verify its requests and drops them. Web SSO for the same LDAP users still works. | NAS: `nas: no reply from radius:1812 after 3 attempts (6s): RADIUS server not responding`. Server log: `invalid Message-Authenticator!  (Shared secret is incorrect.)` | [05-radius-shared-secret-mismatch](runbooks/05-radius-shared-secret-mismatch.md) |

Every scenario is:

- **reproducible:** driven by scripts, with no manual clicking
- **reversible:** `fix.sh` restores a working state
- **idempotent:** `break` and `fix` read the *live* state first (Keycloak Admin API and its LDAP connection test, container clocks, SP trust store, the NAS's secret), so running either twice is a no-op

## Tests

```bash
scripts/test.sh            # build, start or reuse the lab, run every check
scripts/test.sh --fresh    # also delete the volumes first (Keycloak database, directory, NAS secret), so everything is re-created
scripts/test.sh --down     # stop the lab afterwards
```

The 64 checks cover:

- container health, the OIDC issuer, both apps over TLS verified against the lab CA, and an `ldapwhoami` bind as Keycloak's service account over LDAPS
- a real Chromium login to each app, as a local user (alice) and as an LDAP user (dave)
- a RADIUS login from the NAS as dave (Access-Accept), and with a wrong password (Access-Reject)
- for every scenario: break (twice), detected as broken, the exact error in the browser (or in the NAS's output), the matching log line, fix (twice), detected as healthy, and a successful login again
- for `ldap-bind-failure`, also that alice (a local user) still logs in while LDAP users can't; for `radius-shared-secret-mismatch`, that dave still logs in to the OIDC app while RADIUS is broken

Screenshots, page HTML and a full log go to `test-results/`. [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the same script on `ubuntu-latest` with `LAB_HOST=localhost`.

## Rotating secrets

```bash
scripts/setup.sh --rotate     # new random value for every secret in .env; certificates untouched
scripts/test.sh --fresh       # recreate the lab with them, then prove it still works
```

`--rotate` replaces `KC_ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, `DEMO_PASSWORD`, `OIDC_CLIENT_SECRET`, `LDAP_ADMIN_PASSWORD`, `LDAP_BIND_PASSWORD`, `RADIUS_LDAP_BIND_PASSWORD`, `RADIUS_SECRET` and the two apps' session keys. It prints none of them.

The second step matters. Postgres, the Keycloak admin account, the demo users, the OIDC client secret and the directory's passwords only receive their values when the databases are first created, and the NAS stores its copy of the RADIUS secret when its volume is first created. `--fresh` deletes the Keycloak, LDAP and NAS volumes, re-imports the realm, re-seeds the directory and the NAS. That also discards anything you changed by hand in the admin console. Afterwards, look up the new demo password with `grep '^DEMO_PASSWORD=' .env | cut -d= -f2`. Existing browser sessions will no longer work, so sign in again.

When you'd do it:

- **A secret has been seen** somewhere it shouldn't be: a screen share or recording, a screenshot, a chat or support ticket, a terminal transcript, a log, or an AI assistant session.
- **`.env` has left the machine**: copied to another host, a backup or a laptop.
- **Someone no longer needs access**: they had the admin or demo password and shouldn't keep it.
- **Before a demo or handing the lab to someone else**, and periodically as good hygiene.

If a **private key** may have been exposed, especially `certs/ca.key`, rotating `.env` isn't enough. Run `scripts/setup.sh --force` to regenerate the CA, TLS and signing keys as well as the secrets, then `scripts/test.sh --fresh`. Remove the old CA from anywhere you trusted it.

## Troubleshooting

### `ERR_EMPTY_RESPONSE`: "This page isn't working · idlab.home didn't send any data"

**Cause:** you opened an `http://` URL, such as `http://idlab.home:8181`. The lab's ports speak only TLS. When a plain-HTTP request arrives on a TLS port, the server can't parse it and closes the connection without replying. There's no HTTP listener to redirect you to HTTPS. Browsers often autocomplete the `http://` version once you've typed it.

**Fix:** type the full `https://` URL, for example `https://idlab.home:8181/`. If the address bar keeps suggesting the `http://` one, highlight that suggestion and press **Shift+Delete** (Chrome or Edge) to remove it.

**Check from the lab host:**

```bash
curl -sS http://localhost:8181/                                  # curl: (52) Empty reply from server
curl -sS --cacert certs/ca.crt https://localhost:8181/healthz    # {"status":"ok"}
```

## Repository layout

```
.devcontainer/               GitHub Codespaces / dev container: docker-in-docker, runs setup.sh on creation
compose.yaml                 Keycloak, Postgres, OpenLDAP, FreeRADIUS, NAS, saml-sp, oidc-rp, tests (profile "test")
keycloak/idlab-realm.json    realm, clients, demo users and LDAP federation; secrets injected via placeholders
ldap/                        OpenLDAP image: cn=config and directory seed LDIF, first-boot entrypoint
radius/                      FreeRADIUS image: minimal config, clients.conf, LDAP module, the one virtual server
nas/                         NAS image: first-boot secret seeding and nas-auth (one Access-Request)
apps/saml-sp/                Flask + python3-saml service provider
apps/oidc-rp/                Flask + Authlib relying party
scenarios/<name>.sh          detect / break / fix for each scenario
scripts/                     setup, pin-idp-cert, break, fix, status, test, lib
tests/                       Playwright image and e2e.py
runbooks/                    one support runbook per scenario
docs/codespaces.md           step-by-step guide to running the lab in GitHub Codespaces
```

## Design decisions

- **Keycloak in production mode with Postgres**, not `start-dev`. The realm is imported only on first boot. After that, state lives in the database, as in a real deployment. Scenarios change it through the Admin REST API, just as an admin would.
- **HTTPS everywhere, from a local CA.** Recent Keycloak versions have cookie problems over plain HTTP on non-localhost hostnames, and real SSO support happens over TLS. `setup.sh` issues one TLS certificate for `LAB_HOST`, `localhost` and the compose service names. The test browser trusts the CA through Chromium's NSS store rather than ignoring certificate errors.
- **Secrets never leave `.env`.**
  - `setup.sh` generates random values, never prints them, and keeps them on re-runs.
  - Private keys are mode 0600. Containers run as the invoking user's UID so they can still read them.
  - The realm JSON contains only `${PLACEHOLDERS}`.
  - The admin password reaches `curl` on stdin, not in the argument list.
  - `.env`, `certs/` and `.state/` are git-ignored.
- **Keycloak takes its port and scheme from the request.** `KC_HOSTNAME` is just `LAB_HOST`, not a full URL, so Keycloak answers as `https://LAB_HOST:8180` when reached directly and as the proxy's address when reached through the reverse proxy. A full URL would pin one address: logins through the proxy would get the wrong issuer, and the proxy's X-Forwarded headers could never matter, so there would be nothing for the forwarded-headers scenario to break. Three settings go with it:
  - `KC_PROXY_HEADERS=xforwarded`: Keycloak builds its URLs from the proxy's `X-Forwarded-Proto`, `-Host` and `-Port`.
  - `KC_PROXY_TRUSTED_ADDRESSES`: those headers count only when they come from the proxy's fixed address. Anyone else who sends them, including the apps on the compose network, is ignored, so a client can't make Keycloak issue tokens for a host of its choosing.
  - **The OIDC RP rewrites its back-channel endpoints.** Keycloak only accepts `KC_HOSTNAME_BACKCHANNEL_DYNAMIC` with a full URL, so discovery now lists `https://LAB_HOST:8180/...` for every endpoint. With `LAB_HOST=localhost` (CI, Codespaces) that address is the RP's own container, so the RP replaces it with `https://keycloak:8180` for the token, userinfo and JWKS calls it makes itself. Keycloak still sets the issuer from `LAB_HOST` and the port the request arrived on (8180), so tokens carry the same issuer the browser sees.
- **Scenario state is detected, not remembered.** No flag files. `status.sh` reports what the lab is actually doing, so it also catches drift caused by someone editing Keycloak by hand.
- **Why the SAML SP pins the IdP certificate.** The first design had the SP refresh IdP metadata and Keycloak sign with an expired certificate. Building it showed that Keycloak 26.7 won't do that:
  - It refuses to import an expired certificate (`400 "Certificate is not valid"`).
  - When a certificate lapses, it demotes the key (`Certificate chain ... is not valid anymore, disabling it`) and signs with an auto-generated `fallback-RS256` key.
  - A metadata-refreshing SP follows along and never fails.

  Real outages happen at SPs that pinned the certificate at onboarding, so the SP models that. The scenario installs a certificate that is valid for 20 seconds and lets it expire.
- **OpenLDAP built from Debian, not a ready-made image.** The popular OpenLDAP images are either stuck on OpenLDAP 2.4 and unmaintained, or frozen "legacy" builds that no longer get updates. `ldap/Dockerfile` installs Debian's pinned `slapd` 2.6 instead. On first boot, `slapadd` loads `cn=config` and the seed LDIF, with passwords hashed from `.env` (read on stdin, never in argv). After that, the data lives in a volume, just like the realm import.
- **LDAPS, and a dedicated bind account.** Keycloak connects with `ldaps://ldap:1636` and verifies the directory's certificate against the lab CA (`KC_TRUSTSTORE_PATHS`). It binds as `cn=keycloak-svc`, which may read entries but never `userPassword`, and not as the directory administrator. Connection pooling is off so a changed bind credential takes effect on the next request.
- **The LDAP scenario asks Keycloak, not a file.** Keycloak never returns the stored bind password, so `status.sh` uses Keycloak's own connection test (the console's *Test authentication*). Result 49 counts as broken. Anything else, such as the directory being down, is reported as `unknown` rather than mistaken for this scenario.
- **FreeRADIUS from the project's own image, with its stock configuration removed.** `freeradius/freeradius-server:3.2.10` is maintained by the FreeRADIUS project. `radius/Dockerfile` deletes everything it ships except the dictionaries, so nothing such as the example `testing123` client is live, and copies in a configuration small enough to read in one sitting. Secrets reach it as `$ENV{...}` references, expanded at start from `.env`. The NAS image builds on the same pinned image, for its `radclient`.
- **Message-Authenticator is required** from every RADIUS client (BlastRADIUS, CVE-2024-3596), as in current FreeRADIUS defaults. Besides being the secure setting, it makes a wrong shared secret show up as `Shared secret is incorrect` instead of looking like a wrong password; runbook 05 explains why.
- **The RADIUS scenario changes the NAS, not the server.** The NAS keeps its own copy of the shared secret in a volume, as a real NAS keeps it in its configuration. `break.sh` and `fix.sh` write that file through `docker compose exec` on stdin, and `status.sh` compares it with `.env` using `cmp`, so the secret is never on a command line or printed. `nas-auth` reads the user's password on stdin too. It uses `radclient` rather than `radtest`, which takes both the password and the secret as arguments.
- **A fixed subnet for the RADIUS network.** RADIUS servers identify clients by source IP, so the NAS has a fixed address on an internal network (`172.30.181.0/24`, no route off the host). If that subnet clashes with one you already use, change it in `compose.yaml` and `radius/clients.conf` together.
- **python3-saml doesn't check certificate dates.** The SP enforces `notBefore`/`notAfter` on its pinned IdP certificates itself, as many commercial SPs do. The runbook says so.
- **Clock skew without touching the host.** libfaketime is preloaded only in the SP container. It reads its offset from a file on every call, so a scenario can shift the clock without a restart. `FAKETIME_DONT_FAKE_MONOTONIC` is deliberately unset: with libfaketime 0.9.10 it makes Python 3.13's `time.sleep()` fail with `EINVAL`, which crashed gunicorn.
- **lxml and xmlsec are compiled from source** against Debian's libxml2, avoiding the well-known `lxml & xmlsec libxml2 library version mismatch` failure between their binary wheels.
- **Everything is pinned:**
  - images by tag and digest
  - Python packages to fully resolved lock files
  - Debian/Ubuntu packages to exact versions
  - GitHub Actions to commit SHAs

  Each version was at least two weeks old when chosen.
- **Ports 8180–8189 only.** Keycloak also listens on 8180 *inside* its container, and its health endpoint is on the unpublished management port. The directory and the RADIUS server publish no host port at all.

## Known limitations

- **Apt pins can break builds.** Debian removes superseded security updates from its mirrors, so a pinned apt version (for example `libxml2 2.9.14+dfsg-1.3~deb12u6` or `slapd 2.6.10+dfsg-1`) will eventually fail to install. The fix is to bump the pin, or to build from `snapshot.debian.org`.
- **Single-worker apps.** Each app runs one gunicorn worker with an in-memory store for decoded logins. That's fine for a lab, not for production.
- **Tested platform.** The lab has only been tested on x86_64 Linux.
- **Codespaces: no browser logins at the forwarded URLs.** In a codespace, use `scripts/test.sh`, or forward the ports to your own `localhost` (see [Run it in Codespaces](#run-it-in-codespaces)).
- **FreeRADIUS's TLS warning.** At start, FreeRADIUS warns that `libldap is using GnuTLS, while FreeRADIUS is using OpenSSL`. That's how Ubuntu builds the image's libldap. LDAPS to the directory works and is tested, but the warning is real for production; there, use a libldap built against OpenSSL.
- **RADIUS is PAP only.** The NAS sends PAP over the internal network. There's no EAP (802.1X), RadSec or accounting scenario.
- **Not production configuration.** Demo users share one password, the directory and the RADIUS server each run as a single server with no replication or failover, Keycloak's bootstrap admin is used for the scenario scripts, and the SAML SP doesn't do Single Logout.

## How this was built

This project was built with AI-assisted tooling (Claude Code). I directed the scope, design and review. The assistant wrote much of the code and documentation, and every behaviour claimed here is checked by `scripts/test.sh`. Several design changes, such as the certificate pinning and the libfaketime monotonic-clock workaround, came from tests failing against the real software rather than from the first plan.

## License

[MIT](LICENSE)
