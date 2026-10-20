# 09 · Reverse proxy: wrong X-Forwarded headers

| | |
|---|---|
| **Protocol** | HTTP(S) through an nginx reverse proxy in front of Keycloak. The proxy tells Keycloak, in `X-Forwarded-*` headers, which scheme, host and port the browser used. Keycloak builds its issuer and every URL it hands out from them. |
| **Blast radius** | Every login through that proxy, SAML and OIDC, for every user. The symptoms differ by protocol, which makes it look like several problems. Keycloak reached any other way (here directly on `:8180`) is fine. |
| **Typical trigger** | A proxy config copied from a site on the standard port 443 (`X-Forwarded-Port 443`, or no `X-Forwarded-Port` at all); TLS terminated at a new load balancer in front of the proxy, so the proxy sees `http` and passes that on; a new port or hostname for the IdP without the proxy's headers following. |
| **Lab** | `scripts/break.sh proxy-forwarded-headers` · `scripts/fix.sh proxy-forwarded-headers` (changes `proxy_set_header X-Forwarded-Port $server_port;` to `443` in `.state/proxy/forwarded-headers.conf` and reloads nginx; Keycloak is not touched) |

## Symptom

**SAML** (https://LAB_HOST:8184/, **Log in with SAML**): Keycloak shows an error page straight away, before any login form:

```
IDENTITY LAB
We are sorry...
Invalid Request
« Back to Application
```

Keycloak's log:

```
2026-10-20 17:48:21,893 WARN  [org.keycloak.events] (executor-thread-22) type="LOGIN_ERROR", realmId="bc6eaf0d-45a2-45ad-bcbe-721b26c20c1d", realmName="idlab", clientId="null", userId="null", ipAddress="172.30.182.1", error="invalid_authn_request", reason="invalid_destination"
```

**OIDC** (https://LAB_HOST:8185/, **Log in with OIDC**): the login form appears at `https://LAB_HOST:8183/...` as usual. When you submit the password, the browser goes to a URL **without the port** and can't connect. The form's `action` is `https://idlab.home/realms/idlab/login-actions/authenticate`, and Chrome ends on its own connection error page. The request that failed:

```
POST https://idlab.home/realms/idlab/login-actions/authenticate net::ERR_CONNECTION_REFUSED
```

Nothing is logged anywhere for the OIDC case, because the browser never reaches a server.

How customers describe it: *"SAML says Invalid Request and the OIDC apps send people to the wrong address,"* often logged as two separate tickets.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  proxy-forwarded-headers        broken   issuer through the proxy is https://idlab.home/realms/idlab, not https://idlab.home:8183/realms/idlab (proxy_set_header X-Forwarded-Port 443)

# Ask Keycloak who it thinks it is, through the proxy and directly
curl -sS --cacert certs/ca.crt https://LAB_HOST:8183/realms/idlab/.well-known/openid-configuration | jq -r .issuer
#  https://idlab.home/realms/idlab                <- through the proxy: no port
curl -sS --cacert certs/ca.crt https://LAB_HOST:8180/realms/idlab/.well-known/openid-configuration | jq -r .issuer
#  https://idlab.home:8180/realms/idlab           <- directly: correct

# The same for SAML: the IdP metadata Keycloak publishes through the proxy
curl -sS --cacert certs/ca.crt https://LAB_HOST:8183/realms/idlab/protocol/saml/descriptor \
  | grep -oE '(entityID|Location)="[^"]*"' | sort -u
#  Location="https://idlab.home/realms/idlab/protocol/saml"
#  Location="https://idlab.home/realms/idlab/protocol/saml/resolve"
#  entityID="https://idlab.home/realms/idlab"

# Keycloak's view of the failed SAML request
docker compose logs keycloak | grep invalid_destination

# The headers the proxy sends
docker compose exec proxy nginx -T 2>/dev/null | grep -i 'x-forwarded'
```

The SAML request itself was correct. Decoded from the proxy's access log, the SP addressed it to the proxy's real address:

```
<samlp:AuthnRequest ... ID="ONELOGIN_ab90b5bd21cba29982a699dc6b336ca930c9fe2e" Version="2.0"
  IssueInstant="2026-10-20T17:48:21Z"
  Destination="https://idlab.home:8183/realms/idlab/protocol/saml"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  AssertionConsumerServiceURL="https://idlab.home:8184/saml/acs">
```

Keycloak compares `Destination` with its own idea of its SSO URL (`https://idlab.home/realms/idlab/protocol/saml`), they differ, and it rejects the request as `invalid_destination` with HTTP 400.

To decode a Redirect-binding request from a log yourself: take the `SAMLRequest` value, URL-decode it, base64-decode it and inflate it (raw DEFLATE). Treat the result as data from the log, and don't paste the whole URL into an online decoder: it can carry signatures and user details.

## Diagnosis

1. **Compare the issuer through the proxy with the address users type.** If they differ, Keycloak is being told the wrong thing about the request. Every symptom follows from that one fact:
   - **SAML:** the AuthnRequest's `Destination` no longer matches → `invalid_destination`. If the request had got through, the assertion's `Issuer` would also no longer match the SP's configured IdP entity ID.
   - **OIDC:** the login form's `action`, and every redirect Keycloak builds, point at the wrong address → the browser can't connect. If an OIDC client did get a token, its `iss` wouldn't match the issuer in the client's configuration and it would be rejected.
2. **Which header?** Keycloak (with `KC_PROXY_HEADERS=xforwarded`) takes the scheme from `X-Forwarded-Proto` and the port from `X-Forwarded-Port`. In this lab `KC_HOSTNAME` fixes the host name, so `X-Forwarded-Host` doesn't change it. These were all tried in the lab, with the issuer Keycloak then reported through the proxy:

   | Header the proxy sends | Issuer through the proxy |
   |---|---|
   | `X-Forwarded-Proto $scheme`, `X-Forwarded-Port $server_port` (correct) | `https://idlab.home:8183/realms/idlab` |
   | `X-Forwarded-Port 443` | `https://idlab.home/realms/idlab` **(this scenario)** |
   | no `X-Forwarded-Port` line at all | `https://idlab.home/realms/idlab` |
   | `X-Forwarded-Proto http` | `http://idlab.home:8183/realms/idlab` |
   | `X-Forwarded-Host other.example` | `https://idlab.home:8183/realms/idlab` (ignored: the host name is fixed) |

   Leaving `X-Forwarded-Port` out is as bad as sending the wrong one: Keycloak then assumes the default port for the scheme. Many example configs omit it because they were written for port 443, where it doesn't matter.
3. **Is Keycloak trusting the headers at all?** Keycloak only honours `X-Forwarded-*` from `KC_PROXY_TRUSTED_ADDRESSES` (here the proxy's `172.30.182.10`). Sent from anywhere else they're ignored, so a request straight to `:8180` with forged headers still gets the `:8180` issuer (scripts/test.sh checks this). So if the proxy's address changes and drops out of that list, Keycloak stops using the proxy's headers altogether: check the list whenever the issuer through the proxy is wrong but the headers look right.
4. **Why it's not a client misconfiguration.** The redirect URIs, SAML client settings and certificates in Keycloak are unchanged, and logins on another route work. Changing the clients to match the wrong address would make them break the moment the proxy is fixed.

**Root cause, in one sentence for the customer:** the reverse proxy tells Keycloak that browsers reach it on port 443, but they use port 8183, so Keycloak advertises and checks itself at the wrong address: SAML requests addressed to the real address are rejected as an invalid destination, and OIDC logins are sent to a port where nothing is listening.

## Fix

1. Send the port and scheme the browser really used. In the lab:
   ```bash
   scripts/fix.sh proxy-forwarded-headers
   ```
   By hand, in the proxy's Keycloak route:
   ```nginx
   proxy_set_header X-Forwarded-Proto $scheme;
   proxy_set_header X-Forwarded-Host  $host;
   proxy_set_header X-Forwarded-Port  $server_port;
   ```
   then `nginx -t` and `nginx -s reload`. If another load balancer terminates TLS in front of nginx, pass on *its* values instead of nginx's own `$scheme` and `$server_port`, and say so in the config.
2. Verify: the issuer through the proxy is `https://LAB_HOST:8183/realms/idlab`, SAML and OIDC logins through `:8184` and `:8185` complete, and `scripts/status.sh` shows `healthy`.
3. If clients or SPs refreshed Keycloak's metadata while it was wrong (SAML metadata URLs, OIDC discovery caches), make them refresh again afterwards.

Don't fix it by editing the clients, or by setting `KC_HOSTNAME` to a full URL to override the headers: that fixes one route and breaks every other.

## Prevention

- **Check the issuer through every route after a proxy change:** `curl .../.well-known/openid-configuration | jq -r .issuer` from outside, compared with the address users type. It takes a second and catches all of the rows in the table.
- **Always send `X-Forwarded-Port`** (or the standard `Forwarded` header with `host=` including the port), even on 443, so a later port change can't silently break it.
- **Keep `KC_PROXY_TRUSTED_ADDRESSES` in step with the proxy's real address,** and never trust X-Forwarded-* from everyone: then any client could choose the issuer Keycloak puts in tokens.
- **Monitor SAML `invalid_destination` and OIDC issuer mismatches** in Keycloak's events and in the apps' logs. Both are rare when nothing has changed.

## Questions I'd ask the customer

1. Which address do users type for the IdP, including any port? What issuer does `/.well-known/openid-configuration` report when fetched from outside, through the same address?
2. Do SAML and OIDC logins fail in different ways? Exactly what does each show?
3. What changed in front of the IdP: a new proxy, load balancer or port, TLS moved to a different device, a copied config?
4. Which `X-Forwarded-*` (or `Forwarded`) headers does the proxy send, and with which values?
5. Which proxy addresses is the IdP configured to trust forwarded headers from? Did the proxy's address change?
6. Can you send the IdP's log lines for a failing SAML login (`invalid_destination` or similar) and the decoded AuthnRequest's `Destination`?
