# Run the lab in GitHub Codespaces: a beginner's guide

This guide takes you from nothing to logging in, breaking the lab and fixing it, all inside GitHub Codespaces. You don't need Docker or anything else installed on your own computer apart from a browser and, for the logins, Visual Studio Code.

A codespace is a Linux machine in the cloud with this repository already checked out. The lab runs inside it under Docker, exactly as it would on your own Linux host.

## Before you start

**You need:**

- A GitHub account. A free account is enough.
- A web browser.
- [Visual Studio Code](https://code.visualstudio.com/) on your own computer (Windows, macOS or Linux), if you want to log in to the apps yourself. You can create the codespace and run every command without it.

**The free allowance.** GitHub Free accounts get **120 core hours** and **15 GB of storage** a month for Codespaces. This lab uses a **2-core** machine, so each hour it runs uses 2 core hours: about 60 hours of running time a month. Storage is counted for as long as the codespace exists, even when it's stopped. GitHub's [Codespaces billing documentation](https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-codespaces/about-billing-for-github-codespaces) has the current figures.

**The ports.** The lab serves everything over HTTPS on seven ports:

| Port | Service | What it is |
|---|---|---|
| 8180 | Keycloak (IdP) | The identity provider: the login page, and the admin console at `/admin/` |
| 8181 | SAML SP | A sample app that signs you in with SAML |
| 8182 | OIDC RP | A sample app that signs you in with OpenID Connect |
| 8183 | Proxy: Keycloak | The same Keycloak, through an nginx reverse proxy |
| 8184 | Proxy: SAML SP | A second copy of the SAML app, reachable only through the proxy |
| 8185 | Proxy: OIDC RP | A second copy of the OIDC app, reachable only through the proxy |
| 8186 | Egress: OIDC RP | A third copy of the OIDC app, whose own calls to Keycloak go through a Squid egress proxy |

You only need 8183 to 8185 for the reverse proxy scenarios (6 to 10 in [step 5](#5-break-it-and-fix-it)), and 8186 for the egress proxy scenarios (11 to 14). The egress proxy itself has no port of its own.

**The demo users.** You'll use two of the six:

- `alice` lives in Keycloak's own database.
- `dave` lives in the LDAP directory, which Keycloak and the RADIUS server both read.

Both share one randomly generated password. It isn't written in the repository: the README's [Demo users](../README.md#demo-users) section explains how to show it on your own screen. In short, run this in the codespace's terminal:

```bash
grep '^DEMO_PASSWORD=' .env | cut -d= -f2
```

Don't paste it into chats, tickets or screenshots.

## 1. Create the codespace

1. Open the repository's page on GitHub.
2. Either click the **Open in GitHub Codespaces** badge at the top of the README, or click the green **Code** button, choose the **Codespaces** tab and click **Create codespace on main**.
3. If you used the badge, GitHub shows the options it will use (the `main` branch and a 2-core machine). Click **Create new codespace**.

A browser tab opens with the VS Code editor and a terminal at the bottom. Creating the codespace takes a few minutes. When it's done, it runs `scripts/setup.sh` to generate the lab's own certificates and random secrets inside your codespace. None of them is ever committed.

**What "ready" looks like:** the terminal shows this line, with ` ok ` in green:

```
 ok  setup complete for https://localhost:8180 (Keycloak), :8181 (SAML SP), :8182 (OIDC RP)
    Through the reverse proxy: :8183 (Keycloak), :8184 (SAML SP), :8185 (OIDC RP).
    The OIDC RP behind the egress proxy (Squid): :8186.
```

At this point the lab is set up but not yet running. You start it in [step 3](#3-check-the-lab).

## 2. Open it in desktop VS Code

You can run every command from the browser tab. To log in to the apps yourself, though, open the codespace in VS Code on your own computer.

**Why:** the lab's addresses are `https://localhost:8180`, `https://localhost:8181` and `https://localhost:8182`, 8183 to 8185 through the proxy, and 8186 for the OIDC app behind the egress proxy. Keycloak's issuer, the SAML entity IDs and the OIDC redirect URIs all use them. Desktop VS Code forwards the codespace's ports to `localhost` on your own computer, on the same port numbers, so those addresses work in your browser.

The browser tab offers forwarded links of the form `https://<codespace-name>-8181.app.github.dev` instead. **These don't work for logins.** Each port gets its own hostname with no port number, so Keycloak sends you back to `localhost` and the login fails.

**To open it:**

1. In desktop VS Code, open the Extensions view, search for **GitHub Codespaces** and install it. Sign in to GitHub when asked.
2. In your browser, go to [github.com/codespaces](https://github.com/codespaces).
3. Next to your codespace, click the **...** menu, then **Open in** > **Visual Studio Code**. Allow the browser to open VS Code if it asks.
4. VS Code opens a window connected to the codespace. The bottom-left corner shows **Codespaces** and the codespace's name.
5. Open a terminal in that window: **Terminal** > **New Terminal**. Its prompt is a Linux prompt in the repository folder, not your own computer's.
6. Open the **Ports** tab, next to the terminal. Ports 8180, 8181 and 8182 are listed as Keycloak (IdP), SAML SP and OIDC RP, 8183, 8184 and 8185 as the same three through the proxy, and 8186 as Egress: OIDC RP. Check that the **Forwarded Address** column shows the same number for each, `localhost:8180` to `localhost:8186`. If any number differs, see [Troubleshooting](#troubleshooting).

You can close the browser tab from step 1 now. The rest of this guide uses desktop VS Code.

## 3. Check the lab

Run these in the VS Code terminal connected to the codespace.

**Start the lab.** The first start builds every image and takes several minutes:

```bash
docker compose up -d --wait
scripts/pin-idp-cert.sh
```

`pin-idp-cert.sh` does what an administrator does when onboarding a SAML app: it makes the SAML SP trust Keycloak's current signing certificate. It prints a line like ` ok  pinned 1 IdP signing certificate(s) on the SAML SP`.

**See the containers:**

```bash
docker compose ps
```

Every service (`postgres`, `ldap`, `keycloak`, `saml-sp`, `oidc-rp`, `radius`, `nas`) shows `Up` and `(healthy)`.

**See the lab's state:**

```bash
scripts/status.sh
```

The first part lists the services again. The second part, `scenarios (detected from live state)`, lists every scenario as **healthy** in green.

**Optional: prove everything works.**

```bash
scripts/test.sh --fresh
```

This deletes the lab's data, rebuilds it, and runs real headless-browser logins, RADIUS logins and every scenario. The first run takes about 20 minutes, because it compiles the Squid egress proxy from source. It ends with:

```
  175 checks, 175 passed, 0 failed. Full log: /workspaces/identity-lab/test-results/test.log
```

Screenshots and page HTML for every check go to `test-results/`. `--fresh` also pins the certificate, so you don't need to run `pin-idp-cert.sh` again afterwards.

## 4. Log in in a browser

Use the browser on your own computer. Every address is `https://`: an `http://` address fails with an empty response.

**Accept the certificate warning on each port first.** The lab uses its own certificate authority, which your browser doesn't know, so the first visit to each address shows *"Your connection is not private"* (`NET::ERR_CERT_AUTHORITY_INVALID` in Chrome and Edge). Open each of these and click **Advanced** > **Continue** (or **Proceed**):

- https://localhost:8180
- https://localhost:8181
- https://localhost:8182
- for the proxy scenarios: https://localhost:8183, https://localhost:8184 and https://localhost:8185
- for the egress proxy scenarios: https://localhost:8186

Do them before your first login. Otherwise the hand-off from Keycloak back to an app can stop at a warning page. Don't install the lab's CA as trusted on your computer: the README [explains why](../README.md#dont-install-the-lab-ca-as-trusted-on-your-computer).

**OIDC as alice:**

1. Go to https://localhost:8182 and click **Log in with OIDC**.
2. Keycloak's login page opens on port 8180. Sign in as `alice` with the demo password.
3. You land on **OIDC login succeeded**, with the decoded ID token.

**SAML as alice:**

1. In the same window, go to https://localhost:8181 and click **Log in with SAML**.
2. There's no password prompt this time: Keycloak remembers you from the OIDC login. That's single sign-on.
3. You land on **SAML login succeeded**, with the decoded SAML assertion.

**Then as dave:**

1. Open a **new private window**, so alice's Keycloak session doesn't sign you straight in. Accept the certificate warnings again: private windows ask again.
2. Repeat the OIDC and SAML logins as `dave`. He comes from the LDAP directory, but his pages look the same as alice's.

Logging in as dave once now also matters for the `ldap-bind-failure` scenario later: Keycloak imports a directory user on their first login.

**RADIUS as dave:** in the terminal, send a login from the lab's NAS, the way a switch or VPN gateway would:

```bash
docker compose exec nas nas-auth dave
```

Enter the demo password at `Password for dave:` (nothing appears as you type). You get:

```
nas: Access-Request for dave to radius:1812
nas: Access-Accept
```

Only directory users can log in over RADIUS, so `nas-auth alice` gets `nas: Access-Reject`.

## 5. Break it and fix it

Every scenario follows the same routine:

1. **Break it:** `scripts/break.sh <scenario>`. It prints what it broke and a short *Try it* section. Run `scripts/break.sh` with no name to list the scenarios.
2. **Check it:** `scripts/status.sh` shows the scenario as **broken** in red.
3. **See it as the user does:** for a browser scenario, open a **new private window** (an existing session can hide the error), accept the certificate warnings, and log in as the user in the table below. For the RADIUS scenario, run `docker compose exec nas nas-auth dave`.
4. **Diagnose it:** open the scenario's runbook and follow *Where to look*.
5. **Fix it:** `scripts/fix.sh <scenario>`, then log in again in a new private window. `scripts/status.sh` shows it **healthy** again.

Running `break.sh` or `fix.sh` twice is safe: the second run does nothing.

| # | Scenario | What to try | The error you see | Runbook |
|---|---|---|---|---|
| 1 | `expired-signing-cert` | https://localhost:8181, **Log in with SAML**, as `alice`. `break.sh` waits about 20 seconds for the certificate to expire. | SAML SP error page: `IdP signing certificate expired on <date> UTC; the SP has no valid IdP certificate pinned` | [01](../runbooks/01-expired-signing-cert.md) |
| 2 | `clock-skew` | https://localhost:8181, **Log in with SAML**, as `alice` | SAML SP error page: `Could not validate timestamp: expired. Check system clock.` | [02](../runbooks/02-clock-skew.md) |
| 3 | `redirect-uri-mismatch` | https://localhost:8182, **Log in with OIDC** | Keycloak error page, before any login form: `We are sorry...` `Invalid parameter: redirect_uri` | [03](../runbooks/03-redirect-uri-mismatch.md) |
| 4 | `ldap-bind-failure` | https://localhost:8182, **Log in with OIDC**, as `dave`. alice still logs in. | Keycloak error page after you sign in: `Unexpected error when handling authentication request to identity provider.` A directory user who has never logged in gets `Invalid username or password.` instead. | [04](../runbooks/04-ldap-bind-failure.md) |
| 5 | `radius-shared-secret-mismatch` | `docker compose exec nas nas-auth dave`, with the demo password. dave can still log in to the OIDC app. | After about 6 seconds: `nas: no reply from radius:1812 after 3 attempts (6s): RADIUS server not responding` | [05](../runbooks/05-radius-shared-secret-mismatch.md) |
| 6 | `proxy-bad-gateway` | https://localhost:8185. https://localhost:8182 still works. | nginx error page straight away: `502 Bad Gateway` | [06](../runbooks/06-proxy-bad-gateway.md) |
| 7 | `proxy-gateway-timeout` | https://localhost:8185, **Log in with OIDC**, as `alice` | About 5 seconds after you sign in: `504 Gateway Time-out` | [07](../runbooks/07-proxy-gateway-timeout.md) |
| 8 | `proxy-rate-limit` | https://localhost:8185, **Log in with OIDC**, as `alice` | When you submit the password: `429 Too Many Requests` | [08](../runbooks/08-proxy-rate-limit.md) |
| 9 | `proxy-forwarded-headers` | https://localhost:8184, **Log in with SAML** | Keycloak error page: `We are sorry...` `Invalid Request` | [09](../runbooks/09-proxy-forwarded-headers.md) |
| 10 | `proxy-header-too-large` | https://localhost:8184, **Log in with SAML** | Where the login page should be: `502 Bad Gateway` | [10](../runbooks/10-proxy-header-too-large.md) |
| 11 | `proxy-auth-required` | https://localhost:8186, **Log in with OIDC**, as `alice`. https://localhost:8182 still works. | The app's error page after you sign in: `Tunnel connection failed: 407 Proxy Authentication Required` | [11](../runbooks/11-proxy-auth-required.md) |
| 12 | `proxy-policy-block` | https://localhost:8186, **Log in with OIDC**, as `alice` | The app's error page after you sign in: `Tunnel connection failed: 403 Forbidden` | [12](../runbooks/12-proxy-policy-block.md) |
| 13 | `proxy-tls-interception` | https://localhost:8186, **Log in with OIDC**, as `alice` | The app's error page after you sign in: `certificate verify failed: self-signed certificate in certificate chain` | [13](../runbooks/13-proxy-tls-interception.md) |
| 14 | `proxy-bypass` | https://localhost:8186, **Log in with OIDC** | The app's error page straight away: `Failed to resolve 'keycloak'` | [14](../runbooks/14-proxy-bypass.md) |

For 11 to 13, the error comes straight after **Log in** instead if the app has restarted since its last login: it hasn't fetched Keycloak's settings through the proxy yet.

To put everything back at once, run `scripts/fix.sh --all`.

## 6. Finish up

When you've finished with the lab, **delete the codespace**:

1. Go to [github.com/codespaces](https://github.com/codespaces).
2. Click the **...** menu next to the codespace, then **Delete**.

Stopping a codespace (or letting it stop itself when idle) stops the core hours, but it still uses your storage allowance until you delete it. Everything in it is generated, so you lose nothing you can't re-create: a new codespace generates new secrets and certificates.

## Troubleshooting

| Problem | What's happening | What to do |
|---|---|---|
| The **Ports** tab shows a different local number, such as `localhost:8190` for port 8181 | Something on your own computer already uses that port, for example a local copy of the lab, so VS Code picked another one. The lab's addresses only work on the same numbers. | Stop whatever uses the port on your computer, then in the Ports tab right-click the port and choose **Change Local Address Port** to set it back to the port's own number (8180 to 8186). Or close and reopen the codespace in VS Code. |
| The terminal shows a PowerShell prompt (`PS C:\...>`) or your own computer's shell, and commands like `scripts/status.sh` aren't found | The terminal belongs to your own computer, not the codespace. This happens in a VS Code window that isn't connected to the codespace. | Check the bottom-left corner of the window shows **Codespaces**. If it doesn't, reopen the codespace as in [step 2](#2-open-it-in-desktop-vs-code). Then open a new terminal in that window with **Terminal** > **New Terminal**. |
| `docker compose ps` lists nothing, or services aren't `(healthy)`; the browser can't connect | The lab isn't running. It doesn't start on its own when the codespace is created, and may not be running after the codespace has been stopped. | Run `docker compose up -d --wait`, then `scripts/status.sh`. If that fails, `scripts/test.sh --fresh` rebuilds everything from scratch. |
| A login sends you to an `*.app.github.dev` address, or starts there and fails | You opened the app through the codespace's forwarded link in the browser tab, not through `localhost`. | Open the codespace in desktop VS Code ([step 2](#2-open-it-in-desktop-vs-code)) and use `https://localhost:<port>` in your own browser. |
| A login that used to work now fails with one of the errors in the [scenario table](#5-break-it-and-fix-it) | A scenario is still broken from earlier. | Run `scripts/status.sh` to see which, then `scripts/fix.sh <scenario>`, or `scripts/fix.sh --all` for all of them. |
| GitHub won't start or create a codespace and mentions your usage or spending limit | You've used this month's free core hours or storage. | Delete codespaces you no longer need at [github.com/codespaces](https://github.com/codespaces) to free storage. Core hours reset at the start of the next billing month. Check your usage in your GitHub account's billing settings. |
