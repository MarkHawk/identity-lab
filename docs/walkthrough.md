# Walkthrough: from ticket to fix, with every tool

This walkthrough follows support tickets from the first message to the fix, using identity-lab and the tools built around it. It shows how the pieces fit together, and the order a support engineer would actually work in: reproduce, diagnose, find out when it started and who is affected, fix, then explain it to the customer.

- **Chapters 1 and 2:** nobody can sign in with SAML. An expired IdP signing certificate, followed through token-inspector, Splunk and runbook 01. Then a side ticket about 429s.
- **Chapter 3:** logins fail for everyone after a network change. An egress proxy that now wants credentials, followed through the app's error, Squid's log, Splunk and runbook 11. Then two side tickets: TLS interception, and a proxy that logs nothing because it is bypassed.
- **Chapter 4:** users can sign in, but the API refuses every call with 401. Access tokens issued for the wrong API, followed through the API's `WWW-Authenticate` header, token-inspector, Splunk's API panels and runbook 16. Then two side tickets: tokens that expire after 10 seconds (and how to tell that from clock skew), and a CORS mismatch the API logs as a 200.
- **Chapter 5:** three short tickets at the reverse proxy. A redirect loop from one added header line, a maintenance page left on while every health check stays green (and how a 503 differs from a 502 or 504), and a partner's mutual-TLS calls refused with 400, first for a missing client certificate, then for an expired one. Runbooks 15, 17 and 18.

| Step | Tool | Question it answers |
|---|---|---|
| Reproduce | [identity-lab](https://github.com/MarkHawk/identity-lab) | What does the user actually see? |
| Diagnose | [token-inspector](https://github.com/MarkHawk/token-inspector) | What is wrong with the SAML response, and why? |
| Scope | [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) | When did it start, and who is affected? |
| Fix | [runbook 01](../runbooks/01-expired-signing-cert.md) | What do I change, and how do I stop it happening again? |
| Side ticket | [rate-limit-probe](https://github.com/MarkHawk/rate-limit-probe) | Is a 429 the client's fault or the API's? |
| Chapter 3 | identity-lab, identity-support-splunk, [runbooks 11](../runbooks/11-proxy-auth-required.md), [13](../runbooks/13-proxy-tls-interception.md) and [14](../runbooks/14-proxy-bypass.md) | Is it the IdP, the app, or the proxy between them? |
| Chapter 4 | identity-lab, token-inspector, identity-support-splunk, [runbooks 16](../runbooks/16-api-bearer-401.md) and [19](../runbooks/19-cors-blocked.md) | The login works, so why does the API say no? |
| Chapter 5 | identity-lab, identity-support-splunk, [runbooks 15](../runbooks/15-redirect-loop.md), [17](../runbooks/17-service-unavailable.md) and [18](../runbooks/18-client-cert.md) | What is the proxy's answer telling me? |

**Time:** about 20 minutes for chapters 1 and 2 with the lab running, another 20 for chapter 3, 20 for chapter 4 and 15 for chapter 5. Every step in chapters 1 and 2 also has a route that works without the lab, using the samples bundled with each tool.

**Assumes:** identity-lab is running and every scenario shows **healthy** in `scripts/status.sh`. The tools are cloned next to it (`../token-inspector`, `../identity-support-splunk`, `../rate-limit-probe`), each set up as its own README describes. Times in the examples are UTC.

---

## Chapter 1: the ticket

> "Since this morning nobody can sign in to our app with SSO. It worked yesterday and we haven't changed anything."

"We haven't changed anything" is the most common line in an SSO ticket, and it's usually true. Something changed on the other side, or something changed on its own, such as a certificate reaching its expiry date.

### 1.1 Reproduce it

Check the lab is healthy, then break the scenario:

```bash
scripts/status.sh
scripts/break.sh expired-signing-cert
```

`break.sh` installs an IdP signing certificate that is valid for about 20 seconds, pins it on the service provider (as a real SP pins the IdP certificate at onboarding), and waits for it to expire:

```
==> breaking expired-signing-cert: IdP SAML signing certificate pinned on the SP has expired
==> waiting 20s for the pinned signing certificate to expire
 ok  expired-signing-cert is broken: SP-pinned IdP signing cert EXPIRED Oct 17 13:34:16 2026 GMT
```

### 1.2 See it as the user does

Open a **new private window** (an existing session can hide the error), go to `https://idlab.home:8181/`, click **Log in with SAML** and sign in as `alice`. The SP refuses the login:

```
IdP signing certificate expired on <date> UTC; the SP has no valid IdP certificate pinned
```

The user typed the right password and the IdP accepted it. The failure happens afterwards, when the SP checks the signature on the SAML response. That distinction matters: resetting passwords or checking MFA would waste everyone's time.

### 1.3 Look where support looks first

```bash
docker compose logs saml-sp | grep saml_login_failed
```

The SP logs `saml_login_failed reason=idp_cert_expired`. That's a strong clue, but in a real case you rarely get the SP's own log. Usually all you have is what the customer can send you: a HAR file or a SAML-tracer capture of the failing login. Chapter 2 starts from there.

---

## Chapter 2: diagnose, scope, fix

### 2.1 Diagnose the response with token-inspector

Capture the failing SAML response from the lab while the scenario is still broken (token-inspector's `scripts/capture_from_lab.sh --label expired-signing-cert`, described in its `samples/lab/README.md`), or use the capture that ships with token-inspector:

```bash
cd ../token-inspector
token-inspector samples/lab/expired-signing-cert/saml-response.xml --now 2026-10-17T13:34:20Z
```

`--now` checks the response as at the time it was captured, so its timestamps are judged fairly. The report finds the IdP metadata next to the file and ends with this:

```
== Likely cause ==
  The certificate the SP trusts has expired and the IdP has moved on to a new signing key, so the SP
  no longer trusts the key that signs its logins.
  First:     Give the SP the IdP's current signing certificate, or have it refresh the IdP metadata.
  Runbook:   identity-lab 01-expired-signing-cert
             https://github.com/MarkHawk/identity-lab/blob/main/runbooks/01-expired-signing-cert.md
  Explains:  Response signature, Assertion signature, Signature coverage, Trusted certificate dates,
             Certificate matches trusted

Verdict: 5 problems to fix (5 FAIL, 0 WARN, 6 PASS, 4 SKIP)
```

Five failed checks, one cause. This capture is more interesting than a plain expired certificate: once the certificate lapsed, the IdP rotated to a new signing key, which the SP had never been given. So the response is signed with a perfectly valid key that the SP simply doesn't trust. That's exactly how this outage looks at real customers, and why "it worked yesterday" is true.

No lab? `token-inspector demo rotation` runs the same capture from the package.

### 2.2 Scope it with Splunk: when did it start, and who is affected?

Before you tell a customer anything, you want the incident window. Ship the lab's logs to Splunk with identity-support-splunk's sender:

```bash
cd ../identity-support-splunk
python3 sender/hec_send.py --cacert splunk-ca.pem --tls-server-name SplunkServerDefaultCert docker --since 30m
```

Then open **Identity Support > Support overview**. The "When did it start?" table shows the failure with its first and last occurrence:

| first_seen | last_seen | cause | count | affected | apps | runbook |
|---|---|---|---|---|---|---|
| (time of your first failed login) | (time of your last failed login) | IdP signing certificate expired or rotated; the SP still trusts the old one | (number of failed logins) | not in log | saml-sp | 01-expired-signing-cert |

"not in log" is honest: the SP rejected the response before it trusted who the user was, so its log can't name them. To count affected users you'd look at the IdP's successful logins in the same window, because each one is a user the SP then turned away.

![When did it start?](https://raw.githubusercontent.com/MarkHawk/identity-support-splunk/main/docs/screenshots/when-did-it-start.png)

No Splunk of your own? identity-support-splunk's "Try it in 5 minutes" starts a local Splunk with sample data from a real lab run, including this scenario.

### 2.3 Fix it

[Runbook 01](../runbooks/01-expired-signing-cert.md) covers the full diagnosis, the fix and how to prevent a repeat. In the lab, the fix is one command: it gives the SP the IdP's current certificate.

```bash
scripts/fix.sh expired-signing-cert
scripts/status.sh
```

Open a new private window and sign in to `https://idlab.home:8181/` as alice again. You land on **SAML login succeeded**, and `status.sh` shows every scenario healthy.

### 2.4 Tell the customer

A good reply explains the cause in their terms, says what to do, and how to stop it happening again:

> Your sign-ins are failing because your application still trusts the identity provider's old signing certificate, which expired at <time>. The identity provider has since started signing with a new certificate that your application hasn't been given. To fix it, import the identity provider's current signing certificate into your application (or have it refresh the IdP metadata). To avoid a repeat, add the certificate's expiry date to your calendar, or let the application read the IdP metadata automatically so it picks up new certificates itself.

---

## Side ticket: "our integration keeps getting 429 Too Many Requests"

A second ticket arrives from a different team. Their script calls the identity provider through the company's reverse proxy and keeps being refused.

```bash
scripts/break.sh proxy-rate-limit
```

The proxy now limits requests to Keycloak's `/realms/` paths, so a busy client is refused with `429 Too Many Requests` before the IdP sees it. The question support has to answer is whether the client is retrying too eagerly, or the limit and its headers are wrong. [Runbook 08](../runbooks/08-proxy-rate-limit.md) shows how to run rate-limit-probe against the lab's proxy, with its real output.

rate-limit-probe's demo shows the kind of answer it gives, here for a server that restarts the limit whenever a client retries early:

```bash
cd ../rate-limit-probe
rate-limit-probe demo penalty
```

```
== Likely cause ==
  Each request sent during the limit restarts it, so a client that retries immediately and ignores
  Retry-After never leaves the limit.
  Next step:  Make the client wait for the full Retry-After before retrying, and back off when there
              is none. Check its logs for retries less than 4 s apart after a 429.
```

When the fault is on the API side instead (for example a `Retry-After` shorter than the real wait), it says so: "This is on the API side, not the client's: send this report to the API owner."

Put the lab back afterwards:

```bash
scripts/fix.sh proxy-rate-limit
```

---

## Chapter 3: logins fail after a network change

> "Since last night's network change nobody can log in to our app. The identity provider is up, and our other apps log in fine."

This ticket comes with two useful clues. Something did change, even if the app team didn't change it. And the IdP serves other apps, so it's very likely healthy. The app in question makes its calls to the IdP (discovery, token, userinfo, keys) through the company's egress proxy, and that is where the network team made the change. In the lab, that app is the OIDC RP behind Squid on port 8186 (`oidc-rp-egress`). The direct OIDC RP on 8182 doesn't use the proxy and plays the part of "our other apps".

### 3.1 Reproduce it

```bash
scripts/status.sh
scripts/break.sh proxy-auth-required
```

The proxy team has switched on proxy authentication, and nobody gave the app's servers an account or an exemption:

```
==> breaking proxy-auth-required: the egress proxy requires a login the OIDC RP doesn't have
 ok  proxy-auth-required is broken: auth.conf: auth_param basic program /usr/local/squid/libexec/basic_ncsa_auth /tmp/squid-passwd auth_param basic realm identity-lab egress proxy acl egress_users proxy_auth REQUIRED http_access deny !egress_users (the RP has no proxy credentials)
```

### 3.2 See it as the user does

Open a new private window, go to `https://idlab.home:8186/`, click **Log in with OIDC** and sign in as `alice`. Keycloak accepts the password and sends the browser back to the app, which shows **OIDC login failed**:

```
HTTPSConnectionPool(host='keycloak', port=8180): Max retries exceeded with url: /realms/idlab/protocol/openid-connect/token (Caused by ProxyError('Unable to connect to proxy', OSError('Tunnel connection failed: 407 Proxy Authentication Required')))
Error code   backchannel_failed
Detail       ProxyError
```

This text comes from the app's own error page, so every browser shows it in the same words. Whether the user sees Keycloak's login page first depends on the browser, though. A user who still has a Keycloak session goes straight through it, so to them the app "fails as soon as I click Log in".

As in chapter 1, the user did nothing wrong, and neither did the IdP. The password was accepted. The failure comes afterwards, when the app's server tries to exchange the authorisation code at Keycloak's token endpoint, and that call never gets past the proxy. Users only see the token endpoint failing because the app had already loaded Keycloak's discovery document before the change. If the app restarts, it fails one step earlier, straight after **Log in**, on `/.well-known/openid-configuration`. That's why proxy changes often look as if they "only broke after the restart".

Bob and dave get the same page. It's everyone, as the ticket says.

### 3.3 Look where support looks first

The app logs one line per failure:

```bash
docker compose logs oidc-rp-egress | grep oidc_login_failed
```

```
2026-10-22 09:50:24,951 WARNING oidc-rp event=oidc_login_failed reason=backchannel_failed error='HTTPSConnectionPool(host='"'"'keycloak'"'"', port=8180): Max retries exceeded with url: /realms/idlab/protocol/openid-connect/token (Caused by ProxyError('"'"'Unable to connect to proxy'"'"', OSError('"'"'Tunnel connection failed: 407 Proxy Authentication Required'"'"')))' detail=ProxyError
```

The status code that matters is **407**, not 401. A 401 comes from the server you're talking to: here, Keycloak refusing a client secret. A 407 comes from a proxy on the way, so Keycloak never saw the call. Squid's access log confirms it:

```bash
docker compose logs squid | grep 'CONNECT keycloak'
```

```
1792662614.470     16 172.30.183.3 TCP_TUNNEL/200 7077 CONNECT keycloak:8180 - HIER_DIRECT/172.19.0.5 -
1792662614.481     10 172.30.183.3 TCP_TUNNEL/200 3658 CONNECT keycloak:8180 - HIER_DIRECT/172.19.0.5 -
1792662624.950      0 172.30.183.3 TCP_DENIED/407 3413 CONNECT keycloak:8180 - HIER_NONE/- text/html
1792662627.273      0 172.30.183.3 TCP_DENIED/407 3413 CONNECT keycloak:8180 - HIER_NONE/- text/html
1792662629.744      0 172.30.183.3 TCP_DENIED/407 3413 CONNECT keycloak:8180 - HIER_NONE/- text/html
```

The first two lines are the last good login, tunnelled through to Keycloak. Then the change: `TCP_DENIED/407`, with `-` as the user (the app sent no credentials) and `HIER_NONE/-` (Squid never contacted Keycloak). The first column is epoch seconds: `date -u -d @1792662624.950` gives 09:50:24, the same moment as the app's log line.

In a real case the proxy is usually run by another team, so you ask the customer for the proxy's access log lines for the app server's address at the time of a failed login. The app's error text is often enough to know what to ask for.

### 3.4 Scope it with Splunk

Send the lab's logs to Splunk as in [2.2](#22-scope-it-with-splunk-when-did-it-start-and-who-is-affected), then open **Identity Support > Support overview**. The egress panels are lower down the page. The README's [screenshot of them](https://github.com/MarkHawk/identity-support-splunk/blob/main/docs/screenshots/egress-proxy.png) shows real identity-lab data.

**Forward proxy (egress): CONNECTs over time** counts every call the app makes through Squid. For this run, in 10-second buckets:

| _time | tunnelled | 407 |
|---|---|---|
| 09:50:10 | 2 | 0 |
| 09:50:20 | 0 | 3 |
| 09:50:30 | 2 | 0 |

**Forward proxy (egress): refusals and back-channel failures by likely cause** has one row:

| first_seen | last_seen | cause | count | apps | routes | runbook |
|---|---|---|---|---|---|---|
| 2026-10-22 09:50:24 | 2026-10-22 09:50:29 | Egress proxy wants credentials (407 Proxy Authentication Required) for the app's calls to the IdP, and the app sends none or the wrong ones: check the proxy user in the app's HTTPS_PROXY and the proxy's auth settings | 6 | egress proxy, oidc-rp-egress | keycloak:8180 | 11-proxy-auth-required |

Three failed logins give a count of 6, because each one is logged twice: once by the app and once by Squid. *apps* names both sides, so you know you have the evidence from each.

**When did it start?** shows the same cause, with *affected*:

| first_seen | last_seen | cause | count | affected | apps | routes | runbook |
|---|---|---|---|---|---|---|---|
| 2026-10-22 09:50:24 | 2026-10-22 09:50:29 | Egress proxy wants credentials (407 Proxy Authentication Required) ... | 6 | not in log | egress proxy, oidc-rp-egress | keycloak:8180 | 11-proxy-auth-required |

"not in log" is honest again. The app failed before it got a token, so it never learnt who the user was, and the proxy only sees the app server. Keycloak did authenticate each user, so the IdP's login events for this client in the incident window are where to count them. The lab's Keycloak doesn't write login events to its log, so that count isn't available here.

Select the row to open runbook 11.

### 3.5 Fix it

[Runbook 11](../runbooks/11-proxy-auth-required.md) shows how to confirm it: ask Squid directly from the app's container, read the `Proxy-Authenticate` header in the 407, and prove that the app's service account gets through when it sends credentials. In the lab, the fix puts the proxy back as it was, exempting the app servers' network:

```bash
scripts/fix.sh proxy-auth-required
```

```
==> fixing proxy-auth-required
 ok  proxy-auth-required is healthy: auth.conf: (no directives)
```

In a real deployment the lasting fix is one of: an exemption for the app servers by source address, or a service account for the app with its password taken from the app's secret store. Don't put the password in `HTTPS_PROXY`: every `printenv`, `docker inspect` and crash report would then show it. The runbook explains both fixes, and what to do with proxies that only offer NTLM or Kerberos.

### 3.6 Confirm recovery

Sign in at `https://idlab.home:8186/` as alice in a new private window. You land on **OIDC login succeeded**, and Squid tunnels the calls again:

```
1792662634.800     13 172.30.183.3 TCP_TUNNEL/200 7077 CONNECT keycloak:8180 - HIER_DIRECT/172.19.0.5 -
1792662634.812      9 172.30.183.3 TCP_TUNNEL/200 3658 CONNECT keycloak:8180 - HIER_DIRECT/172.19.0.5 -
```

`scripts/status.sh` shows every scenario healthy. Send the logs to Splunk again and the evidence agrees: *tunnelled* is back in the CONNECTs chart from 09:50:30, and the row's *last_seen* stays at 09:50:29 however often you refresh. That last failure time is the end of the incident window for the customer's report.

### 3.7 Tell the customer

> Your logins are failing because of the proxy change, not the identity provider. Since the change, the proxy your application servers use to reach the identity provider asks for credentials (407 Proxy Authentication Required), and the application has none, so it can't complete any login after the password is accepted. The first failure was at 09:50:24 UTC. To fix it, exempt the application servers from proxy authentication, or give the application a proxy service account with its password held in your secret store. For future proxy changes, send app owners the list of server networks and service accounts that will lose access, and test a full login through each app afterwards.

---

## Side ticket: "the app says the IdP's certificate is invalid"

A second team, a second app behind the same proxy. "Our app says the identity provider's certificate is invalid, but it's fine when we open the identity provider in a browser."

```bash
scripts/break.sh proxy-tls-interception
```

The proxy now inspects TLS: it ends the app's TLS session, opens its own to Keycloak, and shows the app a certificate it has issued itself, signed by its own inspection CA. Sign in on 8186 and the app shows:

```
HTTPSConnectionPool(host='keycloak', port=8180): Max retries exceeded with url: /realms/idlab/protocol/openid-connect/token (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain (_ssl.c:1032)')))
Error code   backchannel_failed
Detail       SSLError
```

Both of the customer's observations are true. Keycloak's certificate is fine. The app is shown a different certificate, which the browser never sees, because the browser doesn't use this proxy.

Squid's access log looks healthy at first sight, a `/200`, but it's `NONE_NONE` with 0 bytes, not a `TCP_TUNNEL`:

```
1792662700.792     15 172.30.183.3 NONE_NONE/200 0 CONNECT keycloak:8180 - HIER_DIRECT/172.19.0.5 -
```

The explanation is in Squid's `cache.log`, as an OpenSSL error code:

```
2026/10/22 09:51:40| ERROR: Cannot accept a TLS connection
    problem: failure
    error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000418+TLS_IO_ERR=1
    current master transaction: master99
```

You could decode it by hand (`docker compose exec squid openssl errstr A000418` prints `error:0A000418:SSL routines::tlsv1 alert unknown ca`). The Splunk app does it for you: it extracts `tls_lib_err` and `tls_error` from each `cache.log` event:

| _time | app | signature | tls_lib_err | tls_error |
|---|---|---|---|---|
| 2026-10-22 09:51:40.792 | egress proxy | egress_proxy_tls_untrusted | A000418 | tlsv1 alert unknown ca |
| 2026-10-22 09:51:43.085 | egress proxy | egress_proxy_tls_untrusted | A000418 | tlsv1 alert unknown ca |

*Unknown CA* is the app's TLS library telling the proxy "I don't trust whoever issued this certificate". In the CONNECTs chart these calls show as *intercepted, no tunnel*, and the refusals panel has the row:

| first_seen | last_seen | cause | count | apps | runbook |
|---|---|---|---|---|---|
| 2026-10-22 09:51:40 | 2026-10-22 09:51:43 | Egress proxy intercepts TLS and the app doesn't trust its inspection CA (CERTIFICATE_VERIFY_FAILED; Squid logs the TLS alert, unknown ca): exempt the IdP from interception, or trust the CA in the app | 4 | egress proxy, oidc-rp-egress | 13-proxy-tls-interception |

Two failed logins, four events: the app's error and Squid's `cache.log` line for each. The `NONE_NONE/200` access line isn't counted as a failure, because to Squid the CONNECT succeeded.

[Runbook 13](../runbooks/13-proxy-tls-interception.md) covers the two fixes (exempt the IdP from interception, or add the inspection CA to the app's trust store), and why `verify=False` isn't one of them. Put the lab back:

```bash
scripts/fix.sh proxy-tls-interception
```

---

## Side ticket: "the proxy shows nothing, so it isn't the proxy"

A third app, redeployed this morning, can't log anyone in. The proxy team has already looked: "There's nothing from that server in our logs. It isn't the proxy."

```bash
scripts/break.sh proxy-bypass
```

The redeploy brought a new `NO_PROXY` list that includes the IdP's names. Click **Log in with OIDC** on 8186 and the app fails at once, before any Keycloak page:

```
HTTPSConnectionPool(host='keycloak', port=8180): Max retries exceeded with url: /realms/idlab/.well-known/openid-configuration (Caused by NameResolutionError("HTTPSConnection(host='keycloak', port=8180): Failed to resolve 'keycloak' ([Errno -3] Temporary failure in name resolution)"))
Error code   backchannel_failed
Detail       ConnectionError fetching https://keycloak:8180/realms/idlab/.well-known/openid-configuration
```

The proxy team is right that their logs are empty:

```bash
docker compose logs --since 5m squid | grep 'CONNECT keycloak'
```

prints nothing. But "the proxy shows nothing" isn't an alibi here, it's the symptom. A proxy can only log calls that reach it, and this app depends on the proxy for every call to the IdP. Its network has no direct route out and doesn't resolve external names. So no proxy log lines, at a time when the app should be making calls, means the app has stopped using the proxy. The DNS error points the same way. The app tried to look the IdP up itself, which it never needed to do while it used the proxy.

All the evidence is on the app side, so that's where you ask for it. First, the settings as the running process has them, not as the deployment file says:

```bash
docker compose exec oidc-rp-egress printenv HTTPS_PROXY NO_PROXY
```

```
http://squid:3128
localhost,127.0.0.1,keycloak,.idlab.example
```

Then ask the app's HTTP library what it will do with the IdP's URL:

```bash
docker compose exec oidc-rp-egress python -c "
import requests.utils as u
url = 'https://keycloak:8180/realms/idlab'
print('bypass proxy:', u.should_bypass_proxies(url, no_proxy=None), '| proxies:', u.get_environ_proxies(url))"
```

```
bypass proxy: True | proxies: {}
```

In Splunk, the CONNECTs chart has no new bars at all after the redeploy. It goes quiet rather than red, and quiet is easy to miss. The refusals panel still finds it, from the app's log alone:

| first_seen | last_seen | cause | count | apps | runbook |
|---|---|---|---|---|---|
| 2026-10-22 09:52:18 | 2026-10-22 09:52:20 | Forward proxy is bypassed or misconfigured, even though Squid logs nothing: the app's NO_PROXY includes the IdP, so it calls the IdP directly and cannot resolve or reach it | 2 | oidc-rp-egress | 14-proxy-bypass |

*apps* is only `oidc-rp-egress`. Compare scenarios 11 and 13, where both sides logged. If you only collect the proxy's logs, this outage leaves no trace at all.

Collect the app's logs before anyone fixes it. Changing `NO_PROXY` means recreating the container, and `docker compose logs` only shows the current container's output, so the failed logins disappear with the old container. The same applies to any redeploy on a real platform that doesn't ship its logs elsewhere.

[Runbook 14](../runbooks/14-proxy-bypass.md) covers how `NO_PROXY` matching works in different clients, and how to stop a copied list catching the IdP. Put the lab back:

```bash
scripts/fix.sh proxy-bypass
scripts/status.sh
```

---

## Chapter 4: the app signs in, but the API says 401

> "Since this morning our users can sign in to the app, but the dashboard won't load any data. It says 401. The identity team tidied up some client scopes yesterday, but they say they didn't touch our app."

Two clues again. The login works, so the IdP, the app's client and the user's password are all fine. And something changed at the IdP, even if it wasn't aimed at this app. In the lab the app is the direct OIDC RP on 8182. After login, its **Call the API** button sends the user's access token to the lab's API (`api`, on 8188), which checks the token itself, as most APIs do.

### 4.1 Reproduce it

```bash
scripts/status.sh
scripts/break.sh api-bearer-audience
```

The tidy-up brought the app's client scope in line with staging, and the audience mapper in it now names the staging API:

```
==> breaking api-bearer-audience: oidc-rp's access tokens name another API in their audience
 ok  api-bearer-audience is broken: oidc-rp access tokens get aud idlab-api-staging, the API expects idlab-api
```

### 4.2 See it as the user does

Open a new private window, go to `https://idlab.home:8182/`, click **Log in with OIDC** and sign in as `alice`. You land on **OIDC login succeeded**. Under **API**, click **Call the API**:

```
API call failed: 401 UNAUTHORIZED
Called at (RP clock)   2026-10-23T07:30:52Z
WWW-Authenticate       Bearer realm="idlab-api", error="invalid_token", error_description="The access token audience (idlab-api-staging account) does not include idlab-api"
{"error":"invalid_token","error_description":"The access token audience (idlab-api-staging account) does not include idlab-api"}
```

The same debug page shows why the login still works. The **ID token** is the one the app checks at login, and its audience is the app itself:

```
Audience (aud)   oidc-rp
```

The **access token**, decoded further down the page, is the one the app sends to the API:

```
Audience (aud)            ['idlab-api-staging', 'account']
Authorised party (azp)    oidc-rp
```

Two tokens from one login, checked by two different parties. The app is happy with the first, and the API refuses the second. To the user it looks like "the data is broken". To the app team it looks like "the API is down". Neither is true.

### 4.3 Look where support looks first

Real APIs vary in how much they tell you, so start with the raw answer. In the lab, the debug page's **show the raw token** link (`/debug/access-token`) gives you the access token. For a real customer it's the `Authorization` header of a failing call in a HAR file. Either way it is a live credential until it expires: keep it in a file only you can read, and keep it off the command line.

```bash
umask 077
mkdir -p ~/ticket-1235 && cd ~/ticket-1235
# Save the token as access-token.txt. It starts eyJhbGciOiJSUzI1NiIs... (that's just the JWT header).
printf 'Authorization: Bearer %s\n' "$(cat access-token.txt)" > auth-header.txt
curl -sS -i --cacert ~/identity-lab/certs/ca.crt -H @auth-header.txt https://idlab.home:8188/v1/whoami
```

```
HTTP/1.1 401 UNAUTHORIZED
Server: gunicorn
Date: Fri, 23 Oct 2026 07:31:29 GMT
Connection: keep-alive
Content-Type: application/json
Content-Length: 129
WWW-Authenticate: Bearer realm="idlab-api", error="invalid_token", error_description="The access token audience (idlab-api-staging account) does not include idlab-api"
Cache-Control: no-store
Access-Control-Allow-Origin: https://idlab.home:8182

{"error":"invalid_token","error_description":"The access token audience (idlab-api-staging account) does not include idlab-api"}
```

Read the `WWW-Authenticate` header before anything else. `error="invalid_token"` means a token arrived and the API didn't accept it: expired, badly signed, or meant for someone else. Here the API even says which. Compare a call with no token at all:

```bash
curl -sS -i --cacert ~/identity-lab/certs/ca.crt https://idlab.home:8188/v1/whoami
```

```
HTTP/1.1 401 UNAUTHORIZED
WWW-Authenticate: Bearer realm="idlab-api"
```

The same 401, but no `error`. That one means no token reached the API, which points at a gateway stripping the `Authorization` header, or an app that doesn't send it. And a 403 with `error="insufficient_scope"` would mean a good token without the right scope. The status code alone can't tell these apart. The header can.

The API's log has one line per refused call, with the claims that decided it (never the token):

```bash
docker compose logs api | grep api_token_rejected
```

```
2026-10-23 07:30:52,756 WARNING api event=api_token_rejected error=invalid_token error_description='The access token audience (idlab-api-staging account) does not include idlab-api' sub=1e7d717f-82d0-49ab-bb06-c34330a53287 azp=oidc-rp aud='idlab-api-staging account' iss=https://idlab.home:8180/realms/idlab iat=2026-10-23T07:30:52Z exp=2026-10-23T07:35:52Z
```

and the app logs the call and the answer:

```
2026-10-23 07:30:52,570 INFO oidc-rp event=oidc_login_ok sub=1e7d717f-82d0-49ab-bb06-c34330a53287 email=alice@idlab.example iss=https://idlab.home:8180/realms/idlab elapsed=0.26s
2026-10-23 07:30:52,757 INFO oidc-rp event=api_call url=https://api:8188/v1/whoami status=401 www_authenticate='Bearer realm="idlab-api", error="invalid_token", error_description="The access token audience (idlab-api-staging account) does not include idlab-api"'
```

`oidc_login_ok`, then a 401 from the API a fifth of a second later. Keycloak logs nothing at all: as far as it knows, it issued a token and the login succeeded.

### 4.4 Diagnose the token with token-inspector

Many APIs answer a bare 401 without an `error_description`, so the token is often the only evidence. token-inspector checks it offline, against Keycloak's public keys and what the API expects:

```bash
curl -sS --cacert ~/identity-lab/certs/ca.crt https://idlab.home:8180/realms/idlab/protocol/openid-connect/certs > ~/ticket-1235/jwks.json
cd ../token-inspector
token-inspector ~/ticket-1235/access-token.txt --token-type access \
  --jwks ~/ticket-1235/jwks.json \
  --expect-issuer https://idlab.home:8180/realms/idlab --expect-audience idlab-api \
  --redact --now 2026-10-23T07:31:30Z
```

`--token-type access` stops it applying ID token checks such as the nonce. `--expect-audience` and `--expect-issuer` are what the API is configured to accept. `--redact` masks the user's details so the report can go back into the ticket. token-inspector's `scripts/capture_from_lab.sh --oidc` captures the same tokens from the lab, if you'd rather not copy one by hand. Trimmed to the parts that matter:

```
Checked at: 2026-10-23 07:31:30 UTC, clock skew allowance 60 s
Redacted:   emails, names, NameID and sub are masked

== Claims ==
  exp                 2026-10-23 07:36:22 UTC (in 5 min)
  iat                 2026-10-23 07:31:22 UTC (8 s ago)
  iss                 https://idlab.home:8180/realms/idlab
  aud                 ["idlab-api-staging", "account"]
  sub                 1***
  typ                 Bearer
  azp                 oidc-rp

== Checks ==
  PASS  Signature               Valid RS256 signature, verified with key
                                'Gpp7QBDJqhnyUdSIPHkYXGGpvOqoT5PbP6EFqQp_Mso' from JWKS jwks.json.
  PASS  Expiry (exp)            Valid for another 5 min (exp 2026-10-23 07:36:22 UTC).
  PASS  Issued at (iat)         Issued 2026-10-23 07:31:22 UTC (8 s ago).
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
  Runbook:   identity-lab 16-api-bearer-401
             https://github.com/MarkHawk/identity-lab/blob/main/runbooks/16-api-bearer-401.md
  Explains:  Audience (aud)

Verdict: 1 problem to fix (1 FAIL, 0 WARN, 6 PASS, 4 SKIP)
```

Signature, issuer and expiry pass, so the token is genuine and current. Only the audience is wrong. `azp: oidc-rp` names the client the token was issued to, and that's the client whose settings to look at, not the API's. (`account` is Keycloak's own audience for the user's account console. It's always there and harmless.)

### 4.5 Scope it with Splunk

Send the lab's logs to Splunk as in [2.2](#22-scope-it-with-splunk-when-did-it-start-and-who-is-affected), then open **Identity Support > Support overview** and scroll to the API panels. The README's [screenshot of them](https://github.com/MarkHawk/identity-support-splunk/blob/main/docs/screenshots/api.png) shows real identity-lab data.

**API (bearer tokens): calls over time by result** counts every call the API answered, accepted or refused by reason. For this run, in 10-second buckets (empty ones left out):

| _time | accepted | no_token | wrong_audience |
|---|---|---|---|
| 07:30:50 | 0 | 0 | 1 |
| 07:31:20 | 0 | 0 | 1 |
| 07:31:30 | 0 | 1 | 0 |
| 07:31:40 | 1 | 0 | 0 |

The two *wrong_audience* calls are the browser's and the curl replay from 4.3. The *no_token* call is the curl without a token. The *accepted* call at 07:31:40 is after the fix in 4.6.

**API (bearer tokens): rejections by reason** has the evidence in one row per reason:

| first_seen | last_seen | reason | status | count | clients | audiences |
|---|---|---|---|---|---|---|
| 2026-10-23 07:30:52 | 2026-10-23 07:31:29 | wrong_audience | 401 | 2 | oidc-rp | idlab-api-staging account |
| 2026-10-23 07:31:37 | 2026-10-23 07:31:37 | no_token | 401 | 1 | | |

*clients* is the `azp` of every refused token, and *audiences* what they carried. If a second client's tokens started failing too, it would show up here, and you'd know the change wasn't limited to one app.

**When did it start?** gives the cause in words, with the runbook:

| first_seen | last_seen | cause | count | affected | apps | runbook |
|---|---|---|---|---|---|---|
| 2026-10-23 07:30:52 | 2026-10-23 07:31:29 | API refuses the access token as not meant for it: its audience (aud) does not name the API. The IdP issues the client's tokens for another API: check the audience mapper on the client named in azp | 2 | 1 user | api | 16-api-bearer-401 |

This time *affected* is a number, not "not in log". The API validated the token before refusing it, so it knows the token's subject. **Who is affected?** lists each one by `sub` (here `1e7d717f-82d0-49ab-bb06-c34330a53287`), which the IdP's admin console turns into a user (**Users**, search by ID).

### 4.6 Fix it

[Runbook 16](../runbooks/16-api-bearer-401.md) covers how to find the setting by hand (**Clients > oidc-rp > Client scopes > oidc-rp-dedicated**, the mapper **audience idlab-api**). In the lab:

```bash
scripts/fix.sh api-bearer-audience
```

```
==> fixing api-bearer-audience
 ok  api-bearer-audience is healthy: oidc-rp access tokens get aud idlab-api
```

Tokens issued before the fix keep their old audience until they expire. This app keeps the token it got at login and never asks for a new one, so users have to sign in again (the next side ticket is about that habit).

Don't fix it by making the API accept the staging audience as well. The audience check is what stops a token issued for one API being replayed against another. The lasting fix is in how client settings move between environments: promote them with per-environment values for audiences and URLs, not as copied exports.

### 4.7 Confirm recovery

Sign in again in a new private window and click **Call the API**. You get **API call succeeded: 200 OK**, and the API logs:

```
2026-10-23 07:31:47,188 INFO api event=api_request_ok sub=1e7d717f-82d0-49ab-bb06-c34330a53287 azp=oidc-rp iat=2026-10-23T07:31:47Z exp=2026-10-23T07:36:47Z origin=- cors_allow_origin=https://idlab.home:8182
```

`scripts/status.sh` shows every scenario healthy. In Splunk, *accepted* is back from 07:31:40, and the *wrong_audience* row's *last_seen* stays at 07:31:29.

### 4.8 Tell the customer

> Sign-ins work, but every call to the API is refused because the identity provider has been issuing your app's access tokens for a different API (`idlab-api-staging` instead of `idlab-api`). Yesterday's client scope change copied that setting from staging. The API checks that each token is meant for it, so it correctly refuses them. Sign-ins aren't affected because they use a different token. We've restored the audience. Users need to sign in again to get a corrected token. The first refused call was at 07:30:52 UTC. To stop a repeat, move client settings between environments with per-environment values, and after any client change, test a full sign-in followed by an API call, not just the sign-in.

---

## Side ticket: "it works for a few seconds after login, then fails"

Same app, a different week. "The API works right after I sign in, then every call fails with 401 until I sign in again." The IdP team has been hardening token settings.

```bash
scripts/break.sh api-bearer-expired
```

```
==> breaking api-bearer-expired: oidc-rp's access tokens expire after 10 seconds; the app never refreshes them
 ok  api-bearer-expired is broken: oidc-rp access.token.lifespan=10s, shorter than the RP keeps using its token
```

Sign in and click **Call the API** at once, and it works. Wait 15 seconds and click again:

```
2026-10-23 07:31:58,519 INFO oidc-rp event=api_call url=https://api:8188/v1/whoami status=200 www_authenticate=-
2026-10-23 07:32:16,489 INFO oidc-rp event=api_call url=https://api:8188/v1/whoami status=401 www_authenticate='Bearer realm="idlab-api", error="invalid_token", error_description="The access token expired at 2026-10-23T07:32:11Z"'
```

The first line is the click straight after login. The second is from another login, 15 seconds after it. "Expired" has two common causes that look alike from the outside. Either the token really didn't last long, or the clocks of the IdP and the API disagree ([runbook 02](../runbooks/02-clock-skew.md)). token-inspector, on a token captured from a fresh login and checked 5 seconds after its `exp`:

```bash
token-inspector ~/ticket-1236/access-token.txt --token-type access \
  --jwks ~/ticket-1236/jwks.json \
  --expect-issuer https://idlab.home:8180/realms/idlab --expect-audience idlab-api \
  --redact --now 2026-10-23T07:32:41Z --skew 0
```

```
Checked at: 2026-10-23 07:32:41 UTC, clock skew allowance 0 s

== Claims ==
  exp                 2026-10-23 07:32:36 UTC (5 s ago)
  iat                 2026-10-23 07:32:26 UTC (15 s ago)

== Checks ==
  FAIL  Expiry (exp)            Expired 5 s ago (exp 2026-10-23 07:32:36 UTC). It was issued with a
                                lifetime of only 10 s (iat 2026-10-23 07:32:26 UTC). That lifetime,
                                not clock skew, is the most likely reason: the token runs out almost
                                as soon as it is used.
                                Next: Check the token lifespan set for this client in the IdP (a
                                      value meant as minutes entered as seconds is a common slip),
                                      and that the application refreshes its token before it
                                      expires.
                                Runbook: identity-lab 16-api-bearer-401

== Likely cause ==
  The token was issued with a lifetime of only 10 s and expired 5 s ago, so it runs out before the
  application has finished using it, which can look like clock skew.
```

`--skew 0` matches this API, which allows no clock skew. Without it, token-inspector's default allowance of 60 seconds turns the same failure into a WARN ("Expired 5 s ago, but that is inside the 60 s skew allowance"), with the same likely cause. Always set the skew to the one the receiving side uses, or your report and theirs won't agree.

Two facts separate a short lifetime from clock skew, and both are quick to check:

- **The lifetime** is `exp - iat`: 10 seconds here. Keycloak's default is 300, and most IdPs issue 5 to 60 minutes. A lifetime that short is a setting, not a clock.
- **The clocks** agree:
  ```bash
  docker compose exec keycloak date -u +%FT%TZ
  docker compose exec api date -u +%FT%TZ
  ```
  ```
  2026-10-23T07:32:39Z
  2026-10-23T07:32:40Z
  ```
  With real clock skew, a call straight after login would fail as well. Here it works.

Splunk shows the lifetime without any token at all, because the API logs `iat` and `exp` on every line. The rejections panel:

| first_seen | last_seen | reason | status | count | clients | audiences | lifetime |
|---|---|---|---|---|---|---|---|
| 2026-10-23 07:32:16 | 2026-10-23 07:32:16 | expired | 401 | 1 | oidc-rp | idlab-api account | 10 s |

and **When did it start?** adds it to the cause: "API refuses the access token as expired: the app keeps the token from login instead of refreshing it, or the IdP's access token lifespan for the client is very short. Token lifetime (exp - iat): 10 s, very short: check the client's access token lifespan in the IdP".

The shortened lifespan is only half of it. The app keeps the token it got at login and never refreshes it, so with the normal 5-minute lifespan it fails the same way five minutes after login. The hardening just made an old bug visible. [Runbook 16](../runbooks/16-api-bearer-401.md) covers both fixes: put the lifespan back, and make the app refresh its token before `exp`. Making access tokens last for hours isn't one of them. Put the lab back:

```bash
scripts/fix.sh api-bearer-expired
```

---

## Side ticket: "the API logged a 200, so it isn't us"

A front-end team has moved the dashboard's API calls into the browser: the page's own script now calls the API. "The page says *Failed to fetch*." The API team has looked: "Every one of those calls is a 200 in our logs. It isn't the API."

```bash
scripts/break.sh cors-blocked
```

```
==> breaking cors-blocked: the API's Access-Control-Allow-Origin has a trailing slash: browsers block its answers
 ok  cors-blocked is broken: the API sends Access-Control-Allow-Origin: https://idlab.home:8182/ for origin https://idlab.home:8182
```

Sign in on 8182 and click **Call the API from the browser**. The page knows almost nothing:

```
API call from the browser failed: TypeError: Failed to fetch
The browser gave this page no response. Its developer console (F12) says why.
```

The browser's console does:

```
Access to fetch at 'https://idlab.home:8188/v1/whoami' from origin 'https://idlab.home:8182' has been blocked by CORS policy: The 'Access-Control-Allow-Origin' header has a value 'https://idlab.home:8182/' that is not equal to the supplied origin. Have the server send the header with a valid value.
Failed to load resource: net::ERR_FAILED
```

The API team is right about their logs:

```bash
docker compose logs api | grep -E 'cors_preflight|api_request_ok'
```

```
2026-10-23 07:33:05,068 INFO api event=api_cors_preflight origin=https://idlab.home:8182 method=GET headers=authorization
2026-10-23 07:33:05,073 INFO api event=api_request_ok sub=1e7d717f-82d0-49ab-bb06-c34330a53287 azp=oidc-rp iat=2026-10-23T07:33:04Z exp=2026-10-23T07:38:04Z origin=https://idlab.home:8182 cors_allow_origin=https://idlab.home:8182/
```

The browser asked first (the preflight, an `OPTIONS` request), was told yes, sent the real call with the token, and the API validated it and answered 200. Then the browser threw the answer away, because CORS is enforced by the browser, on the response, after the server has done its work. A 200 in the API's log only proves the API is happy. Whether the page could read the answer is decided afterwards, in the browser.

The last field on the second line is the cause: `cors_allow_origin=https://idlab.home:8182/`. An origin is scheme, host and port, with no path, and the browser compares the header with the page's origin as an exact string. `curl` shows the difference between the two answers:

```bash
curl -sS -o /dev/null -D - --cacert certs/ca.crt -X OPTIONS -H 'Origin: https://idlab.home:8182' \
  -H 'Access-Control-Request-Method: GET' -H 'Access-Control-Request-Headers: authorization' \
  https://idlab.home:8188/v1/whoami
curl -sS -o /dev/null -D - --cacert certs/ca.crt -H 'Origin: https://idlab.home:8182' https://idlab.home:8188/healthz
```

```
HTTP/1.1 204 NO CONTENT
Access-Control-Allow-Origin: https://idlab.home:8182
Access-Control-Allow-Methods: GET
Access-Control-Allow-Headers: Authorization
Access-Control-Max-Age: 600

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://idlab.home:8182/
```

The preflight is answered by one layer (as a gateway often does) and gets it right. The real response's header is set somewhere else, and someone pasted the origin from the browser's address bar, trailing slash and all. And the app's own server-side call to the API (**Call the API**) still works throughout, because CORS is a browser rule and a server isn't bound by it. So "it works from our server" doesn't rule CORS out either.

In Splunk this call isn't a rejection at all, which is why the API team sees nothing wrong. The calls-over-time chart has it as *cors_origin_mismatch*, an accepted call whose header didn't match the calling page's origin:

| _time | accepted | cors_origin_mismatch |
|---|---|---|
| 07:33:00 | 0 | 1 |
| 07:33:10 | 1 | 0 |

and **When did it start?** names the cause: "Browser blocks the API's answer (CORS), though the API logged a success: its Access-Control-Allow-Origin (cors_allow_origin) is not exactly the calling page's origin, for example a trailing slash, http versus https, a port, or a new front-end origin not on the allow-list", with runbook 19. The *accepted* call at 07:33:10 is the server-side **Call the API**, made while the browser's calls were still being blocked.

[Runbook 19](../runbooks/19-cors-blocked.md) covers fixing it in the layer that sets the header on real responses, and why `*` or echoing back any `Origin` isn't the fix. Put the lab back:

```bash
scripts/fix.sh cors-blocked
scripts/status.sh
```

---

## Chapter 5: trouble at the front door

The reverse proxy is the front door: every browser and partner system that reaches the IdP or an app through it on 8183 to 8189 goes past it first. That makes it the first suspect in a lot of tickets, and often the right one, but rarely for the reason the ticket gives. This chapter is three short tickets from one afternoon. Each one is solved by reading the proxy's answer and one or two fields of its access log, before anyone logs in to the IdP.

The lab's nginx writes one access log line per request, with `upstream=` (where it sent the request, or `-` if nowhere) and `upstream_status=` (what came back). On the mutual-TLS route it adds what it made of the client's certificate. Those fields do most of the work below.

### 5.1 "Too many redirects, and clearing cookies didn't help"

> "Since this morning's proxy change, our app just says it redirected too many times. We cleared cookies and tried another browser. Nothing helps."

```bash
scripts/break.sh redirect-loop
```

```
==> breaking redirect-loop: the proxy stops sending X-Forwarded-Proto to an app that forces HTTPS
 ok  redirect-loop is broken: GET https://idlab.home:8187/ redirects to itself (edge-location.conf: proxy_set_header X-Request-ID $request_id)
```

Open `https://idlab.home:8187/` and the app never appears. Chrome gives up with its own page:

```
This page isn't working
idlab.home redirected you too many times.
Try deleting your cookies.
ERR_TOO_MANY_REDIRECTS
```

There's no login to try, so there's nothing for the user to have done wrong. Browsers suggest cookies because a loop between two pages usually is a cookie problem. `curl` shows this one is different:

```bash
curl -sS -I --cacert certs/ca.crt https://idlab.home:8187/
curl -sS -o /dev/null -L --max-redirs 5 -w '%{http_code} after %{num_redirects} redirects\n' --cacert certs/ca.crt https://idlab.home:8187/
```

```
HTTP/1.1 302 FOUND
Server: nginx
Location: https://idlab.home:8187/

curl: (47) Maximum (5) redirects followed
302 after 5 redirects
```

The page redirects to itself: the `Location` is the URL that was asked for. No cookie is involved, which is why clearing them didn't help. The app says why it redirects, once per request:

```bash
docker compose logs oidc-rp-edge | grep force_https
```

```
2026-10-23 07:37:06,921 INFO oidc-rp event=force_https path=/ scheme=http x_forwarded_proto=-
```

TLS ends at the proxy, so the app always receives plain HTTP. It only knows the browser used HTTPS because the proxy tells it in `X-Forwarded-Proto`, and now that header arrives empty (`-`). So the app "upgrades" the browser to HTTPS, the URL it's already on, and the browser follows until it gives up. The proxy's log agrees: every request reached the app (`upstream=` has an address), and the app answered 302 each time:

```
172.30.182.1 "GET / HTTP/1.1" 302 235 host=idlab.home:8187 upstream=172.30.182.3:8182 upstream_status=302 request_time=0.002 upstream_time=0.001
```

The proxy change was one line, a request ID for tracing, added to the app's `location`:

```nginx
proxy_set_header X-Request-ID $request_id;
```

That line is harmless in itself. The trap is an nginx rule: a `location` with any `proxy_set_header` of its own inherits none from the `server` block. The server's `X-Forwarded-Proto`, `X-Forwarded-For` and `Host` lines silently stopped applying to this app.

In Splunk, **When did it start?** counts loops, not redirects. The browser gave up once and the `curl -L` once, so the count is 2:

| first_seen | last_seen | cause | count | affected | apps | routes | runbook |
|---|---|---|---|---|---|---|---|
| 2026-10-23 07:37:00 | 2026-10-23 07:37:06 | Redirect loop (too many redirects): the app forces HTTPS but gets no X-Forwarded-Proto from the reverse proxy, so it sends every request back to the HTTPS URL the browser is already on. Usually a proxy_set_header added to the proxy's location, which drops the headers it inherited | 2 | not in log | oidc-rp-edge | / | 15-redirect-loop |

The **App stuck in a redirect loop** alert fires on a single loop, because a loop is never one user's problem. Its search, for this run, gives 2 loops of 27 redirects on `/` (21 from the browser, 6 from curl). The single `curl -I` isn't counted: one redirect is someone typing `http://`, not a loop.

[Runbook 15](../runbooks/15-redirect-loop.md) shows both fixes: take the line out, or keep it and repeat every header the location needs. It also covers what to do if users still loop after the fix (a cached 301). Put the lab back:

```bash
scripts/fix.sh redirect-loop
```

The proxy's next lines show `upstream_status=200`.

### 5.2 "SSO is down, but every health check is green"

> "Nobody can sign in. Monitoring says the IdP and the proxy are both healthy. Last night's IdP upgrade went fine."

```bash
scripts/break.sh proxy-maintenance
```

```
==> breaking proxy-maintenance: the proxy is left in maintenance mode: 503 for Keycloak, which is healthy
 ok  proxy-maintenance is broken: kc-maintenance.conf: return 503 with a maintenance page (maintenance mode is on)
```

Sign in at `https://idlab.home:8184/` (the SAML SP behind the proxy). Where Keycloak's login form should be, the user gets:

```
Planned maintenance
Sign-in is down for planned maintenance
We are upgrading the sign-in service. Please try again later.
```

The upgrade did go fine. Somebody put the proxy into maintenance mode for it and didn't take it out afterwards. Ask the proxy and Keycloak directly, and both stories hold:

```bash
curl -sS -o /dev/null -D - --cacert certs/ca.crt https://idlab.home:8183/realms/idlab/.well-known/openid-configuration
curl -sS -o /dev/null -w 'nginx-healthz: %{http_code}\n' --cacert certs/ca.crt https://idlab.home:8183/nginx-healthz
curl -sS -o /dev/null -w 'keycloak direct :8180: %{http_code}\n' --cacert certs/ca.crt https://idlab.home:8180/realms/idlab/.well-known/openid-configuration
```

```
HTTP/1.1 503 Service Temporarily Unavailable
Server: nginx
Content-Type: text/html
Retry-After: 3600

nginx-healthz: 200
keycloak direct :8180: 200
```

The proxy's health check is green, and Keycloak on its own port is green. Only the route users take is red, and nothing monitors that route. That's how monitoring and users can disagree.

The three 5xx errors a reverse proxy gives out mean quite different things, and the proxy's access log tells them apart in one field. Here are the 503, and for comparison a 502 and a 504 from the same lab (scenarios `proxy-bad-gateway` and `proxy-gateway-timeout`, broken briefly for the purpose):

```
172.30.182.1 "GET /realms/idlab/.well-known/openid-configuration HTTP/1.1" 503 205 host=idlab.home:8183 upstream=- upstream_status=- request_time=0.000 upstream_time=-
172.30.182.1 "GET / HTTP/1.1" 502 552 host=idlab.home:8185 upstream=172.30.182.4:8182 upstream_status=502 request_time=0.003 upstream_time=0.003
172.30.182.1 "GET /auth/callback?state=***&session_state=***&iss=https%3A%2F%2Fidlab.home%3A8183%2Frealms%2Fidlab&code=*** HTTP/1.1" 504 562 host=idlab.home:8185 upstream=172.30.182.4:8182 upstream_status=504 request_time=5.002 upstream_time=5.002
```

- **503 with `upstream=-`**: the proxy answered by itself, in no time, and never contacted Keycloak. Maintenance mode, or a rate limit set to answer 503. Keycloak is probably fine. Look at the proxy's configuration.
- **502 with an upstream address**: the proxy reached the app, but what came back wasn't a valid HTTP answer (here, plain HTTP sent to an HTTPS port). Look at `proxy_pass` ([runbook 06](../runbooks/06-proxy-bad-gateway.md)).
- **504 with an upstream address and `request_time=5.002`**: the proxy waited its full read timeout of 5 seconds and gave up. Look at what the app is waiting for ([runbook 07](../runbooks/07-proxy-gateway-timeout.md)).

`Retry-After: 3600` fits the first case too. It's something a person put there, not something a failing server sends. (The lab masks the SAML and OIDC parameters in the proxy's log as `***`, and so should yours: an authorisation code or a SAML request has no place in a ticket.)

In Splunk, the **Reverse proxy: responses over time** chart has the 503s in their own colour, and **Reverse proxy: refusals by likely cause** keeps them separate from the 502 and the 504:

| first_seen | last_seen | cause | count | routes | runbook |
|---|---|---|---|---|---|
| 2026-10-23 07:37:31 | 2026-10-23 07:37:37 | Reverse proxy answered 503 itself, without passing the request on (no upstream): maintenance mode or a return 503 left on, while the IdP behind it is probably fine. If the error log says limiting requests at the same moment, it is the rate limit instead (runbook 08) | 2 | idlab.home:8183 | 17-service-unavailable |
| 2026-10-23 07:37:58 | 2026-10-23 07:37:58 | Reverse proxy got no valid answer from the app behind it (502): check proxy_pass (http:// versus https://, port) and that the app is where the proxy expects | 1 | idlab.home:8185 | 06-proxy-bad-gateway |
| 2026-10-23 07:38:08 | 2026-10-23 07:38:08 | Reverse proxy gave up waiting for the app behind it (504): the app, or something it calls, is slower than the proxy's read timeout | 1 | idlab.home:8185 | 07-proxy-gateway-timeout |

The README's [screenshot of the reverse proxy panels](https://github.com/MarkHawk/identity-support-splunk/blob/main/docs/screenshots/proxy.png) shows the same layout with real identity-lab data. The 503 has no alert, by design: maintenance pages are meant to happen. It shows in the dashboard instead, and in **When did it start?** with `proxy` as the app.

[Runbook 17](../runbooks/17-service-unavailable.md) covers turning it off safely (ask whoever turned it on whether the work is really finished) and making maintenance mode expire on its own. Put the lab back:

```bash
scripts/fix.sh proxy-maintenance
```

```
==> fixing proxy-maintenance
 ok  proxy-maintenance is healthy: kc-maintenance.conf: (no directives)
```

Users can retry straight away. Browsers don't cache a 503.

### 5.3 "The partner's calls fail with 400 Bad Request"

> "Our partner integration calls your mutual-TLS endpoint, and since their redeploy every call gets 400 Bad Request. TLS works, they say, so it can't be the certificate."

The mutual-TLS route on 8189 is for partner systems: nginx asks the client for a certificate during the TLS handshake, checks it against the lab CA, and only then answers. The partner's redeploy left its certificate and key behind:

```bash
scripts/break.sh client-cert-missing
```

```
==> breaking client-cert-missing: the mTLS client lost its certificate and connects without one (nginx 496)
 ok  client-cert-missing is broken: the client has no certificate in .state/mtls-client
```

The partner is right that TLS works:

```bash
curl -sS -v --cacert certs/ca.crt https://idlab.home:8189/ 2>&1 | grep -E 'Request CERT|SSL connection using|^< HTTP|<title>'
```

```
* TLSv1.3 (IN), TLS handshake, Request CERT (13):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768 / RSASSA-PSS
< HTTP/1.1 400 Bad Request
<head><title>400 No required SSL certificate was sent</title></head>
```

The server asked for a certificate (`Request CERT`), the client didn't send one, and nginx finished the handshake anyway. It refuses the request afterwards, with a 400 and an error page that says why. So "TLS works" and "it's the certificate" are both true. A browser shows the same page:

```
400 Bad Request
No required SSL certificate was sent
nginx
```

A week later, the same partner, the same 400. This time they're sure they send their certificate. They do, but it expired yesterday:

```bash
scripts/fix.sh client-cert-missing
scripts/break.sh client-cert-expired
```

```
==> breaking client-cert-expired: the mTLS client's certificate has expired (nginx 495)
 ok  client-cert-expired is broken: the client certificate does not verify: error 10 at 0 depth lookup: certificate has expired (subject=CN=partner-client notAfter=Oct 22 07:38:33 2026 GMT)
```

The user gets `400 Bad Request` again, with *The SSL certificate error* on the page. Two different causes give the user the same status code, which is why "we get a 400" isn't enough to go on. The proxy's error log names each one, in nginx's words:

```bash
docker compose logs proxy | grep -E 'no required SSL certificate|certificate verify error'
```

```
2026/10/23 07:38:22 [info] 5656#5656: *998 client sent no required SSL certificate while reading client request headers, client: 172.30.182.1, server: , request: "GET / HTTP/1.1", host: "idlab.home:8189"
2026/10/23 07:38:35 [info] 5656#5656: *1005 client SSL certificate verify error: (10:certificate has expired) while reading client request headers, client: 172.30.182.1, server: , request: "GET / HTTP/1.1", host: "idlab.home:8189"
```

and the access log has the same in fields you can search on:

```
172.30.182.1 "GET / HTTP/1.1" 400 230 host=idlab.home:8189 client_dn="-" client_not_after="-" ssl_client_verify=NONE
172.30.182.1 "GET / HTTP/1.1" 400 610 host=idlab.home:8189 client_dn="CN=partner-client" client_not_after="Oct 22 07:38:33 2026 GMT" ssl_client_verify=FAILED:certificate has expired
```

Note that these lines are logged at `info`. An error log left at the default `error` level hides both, and the whole incident is a row of anonymous 400s.

Splunk's **Reverse proxy: client certificates on mutual-TLS routes** is the table to check, and not only when something has broken:

| client | not_after | days_left | result | count | first_seen | last_seen | routes |
|---|---|---|---|---|---|---|---|
| CN=partner-client | Nov 23 18:32:36 2027 GMT | 396 | accepted | 2 | 2026-10-23 07:38:32 | 2026-10-23 07:38:44 | idlab.home:8189 |
| CN=partner-client | Oct 22 07:38:33 2026 GMT | -2 | refused: certificate has expired | 2 | 2026-10-23 07:38:35 | 2026-10-23 07:38:35 | idlab.home:8189 |
| no certificate sent | - | | refused: no certificate | 2 | 2026-10-23 07:38:16 | 2026-10-23 07:38:22 | idlab.home:8189 |

Each certificate a client presents gets its own row with its expiry date, so the *accepted* row is the early warning. `days_left` of 396 is plenty. A known partner's certificate under 30 days is the moment to email them, not the day it fails. (The expired certificate ran out just over a day before this run, and the panel rounds down, so it shows -2.)

**When did it start?** has both causes, and here *affected* is a certificate, not a user, because a partner system is the client:

| first_seen | last_seen | cause | count | affected | apps | routes | runbook |
|---|---|---|---|---|---|---|---|
| 2026-10-23 07:38:16 | 2026-10-23 07:38:22 | Client sent no certificate to a mutual-TLS route (400, ssl_client_verify=NONE): its certificate and key are missing from its deployment or configuration, or a TLS-inspecting proxy in between drops it | 2 | not in log | proxy | idlab.home:8189 | 18-client-cert |
| 2026-10-23 07:38:35 | 2026-10-23 07:38:35 | Client certificate on a mutual-TLS route has expired (400, ssl_client_verify=FAILED:certificate has expired): renew it; client_not_after has the date | 2 | client certificate (CN=partner-client) | proxy | idlab.home:8189 | 18-client-cert |

[Runbook 18](../runbooks/18-client-cert.md) covers both fixes: restore the certificate to the client's deployment, or have the partner get a new one from the CA you trust. It also explains why `ssl_verify_client optional_no_ca` and accepting expired certificates aren't fixes. Put the lab back:

```bash
scripts/fix.sh client-cert-expired
scripts/status.sh
```

```
==> fixing client-cert-expired
 ok  client-cert-expired is healthy: the client certificate verifies (subject=CN=partner-client notAfter=Nov 23 18:32:36 2027 GMT)
```

---

## Coming next

- **Directory and RADIUS outages** (scenarios 04 and 05), with packet-level evidence from a planned RADIUS and LDAP pcap analyser.
- **The remaining scenarios** (02, 03, 09, 10 and 12) have runbooks but no chapter yet.
- **An AI triage assistant** that reads a ticket and suggests the likely cause and runbook, using these runbooks as its knowledge base.
