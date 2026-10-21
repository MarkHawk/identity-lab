# Walkthrough: one incident, every tool

This walkthrough follows a single support ticket from the first message to the fix, using identity-lab and the tools built around it. It shows how the pieces fit together, and the order a support engineer would actually work in: reproduce, diagnose, find out when it started and who is affected, fix, then explain it to the customer.

| Step | Tool | Question it answers |
|---|---|---|
| Reproduce | [identity-lab](https://github.com/MarkHawk/identity-lab) | What does the user actually see? |
| Diagnose | [token-inspector](https://github.com/MarkHawk/token-inspector) | What is wrong with the SAML response, and why? |
| Scope | [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) | When did it start, and who is affected? |
| Fix | [runbook 01](../runbooks/01-expired-signing-cert.md) | What do I change, and how do I stop it happening again? |
| Side ticket | [rate-limit-probe](https://github.com/MarkHawk/rate-limit-probe) | Is a 429 the client's fault or the API's? |

**Time:** about 20 minutes with the lab running. Every step also has a route that works without the lab, using the samples bundled with each tool.

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

## Coming next

- **Directory and RADIUS outages** (scenarios 04 and 05), with packet-level evidence from a planned RADIUS and LDAP pcap analyser.
- **Forward proxy problems** (scenarios 11 to 14) in the Splunk app.
- **An AI triage assistant** that reads a ticket and suggests the likely cause and runbook, using these runbooks as its knowledge base.
