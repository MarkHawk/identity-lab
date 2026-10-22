# Walkthrough: from ticket to fix, with every tool

This walkthrough follows support tickets from the first message to the fix, using identity-lab and the tools built around it. It shows how the pieces fit together, and the order a support engineer would actually work in: reproduce, diagnose, find out when it started and who is affected, fix, then explain it to the customer.

- **Chapters 1 and 2:** nobody can sign in with SAML. An expired IdP signing certificate, followed through token-inspector, Splunk and runbook 01. Then a side ticket about 429s.
- **Chapter 3:** logins fail for everyone after a network change. An egress proxy that now wants credentials, followed through the app's error, Squid's log, Splunk and runbook 11. Then two side tickets: TLS interception, and a proxy that logs nothing because it is bypassed.

| Step | Tool | Question it answers |
|---|---|---|
| Reproduce | [identity-lab](https://github.com/MarkHawk/identity-lab) | What does the user actually see? |
| Diagnose | [token-inspector](https://github.com/MarkHawk/token-inspector) | What is wrong with the SAML response, and why? |
| Scope | [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) | When did it start, and who is affected? |
| Fix | [runbook 01](../runbooks/01-expired-signing-cert.md) | What do I change, and how do I stop it happening again? |
| Side ticket | [rate-limit-probe](https://github.com/MarkHawk/rate-limit-probe) | Is a 429 the client's fault or the API's? |
| Chapter 3 | identity-lab, identity-support-splunk, [runbooks 11](../runbooks/11-proxy-auth-required.md), [13](../runbooks/13-proxy-tls-interception.md) and [14](../runbooks/14-proxy-bypass.md) | Is it the IdP, the app, or the proxy between them? |

**Time:** about 20 minutes for chapters 1 and 2 with the lab running, and another 20 for chapter 3. Every step in chapters 1 and 2 also has a route that works without the lab, using the samples bundled with each tool.

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

## Coming next

- **Directory and RADIUS outages** (scenarios 04 and 05), with packet-level evidence from a planned RADIUS and LDAP pcap analyser.
- **An AI triage assistant** that reads a ticket and suggests the likely cause and runbook, using these runbooks as its knowledge base.
