# 11 · Egress proxy: 407 Proxy Authentication Required

| | |
|---|---|
| **Protocol** | HTTPS from an app server to the IdP through a forward ("egress") proxy. The app sends `CONNECT keycloak:8180` to the proxy and expects a tunnel. Here that is the OIDC RP's back channel: discovery, token, userinfo and JWKS. The browser side of the login doesn't use the proxy. |
| **Blast radius** | Every app whose outbound calls go through that proxy and that has no proxy credentials. In the lab, the OIDC RP at `https://LAB_HOST:8186`. The direct OIDC RP (`:8182`) has no proxy and keeps working. Keycloak is healthy and never sees the failed calls. |
| **Typical trigger** | The proxy team turns on authentication (for auditing, or a new "every connection must have a user" policy) and the exemption for server networks or service accounts is missing. Also: a service account's proxy password expires or is rotated, or the proxy moves from Basic to NTLM or Kerberos authentication, which many server-side HTTP clients can't do. |
| **Lab** | `scripts/break.sh proxy-auth-required` · `scripts/fix.sh proxy-auth-required` (adds Basic authentication to Squid in `.state/squid/auth.conf` and runs `squid -k reconfigure`; the RP isn't touched) |

## Symptom

Go to https://LAB_HOST:8186/, click **Log in with OIDC** and sign in as `alice`. Keycloak accepts the password. The browser comes back to the app, which shows **OIDC login failed** with:

```
HTTPSConnectionPool(host='keycloak', port=8180): Max retries exceeded with url: /realms/idlab/protocol/openid-connect/token (Caused by ProxyError('Unable to connect to proxy', OSError('Tunnel connection failed: 407 Proxy Authentication Required')))
Error code   backchannel_failed
Detail       ProxyError
```

The user did sign in to Keycloak, but the app couldn't redeem the authorisation code, because the proxy refused to open a tunnel to the token endpoint. The browser gets a `502` from the app.

If the app has restarted since its last successful login, the failure comes earlier: straight after **Log in**, before Keycloak's page. The app hasn't loaded Keycloak's discovery document yet, and that is the first call that fails:

```
HTTPSConnectionPool(host='keycloak', port=8180): Max retries exceeded with url: /realms/idlab/.well-known/openid-configuration (Caused by ProxyError('Unable to connect to proxy', OSError('Tunnel connection failed: 407 Proxy Authentication Required')))
Detail       ProxyError fetching https://keycloak:8180/realms/idlab/.well-known/openid-configuration
```

The app (Authlib) keeps discovery and Keycloak's signing keys in memory for as long as it runs. So a proxy change can look as if it "only broke after the restart", or only at the token step.

The app logs one line per failure:

```
2026-10-21 08:26:17,594 WARNING oidc-rp event=oidc_login_failed reason=backchannel_failed error='HTTPSConnectionPool(host='"'"'keycloak'"'"', port=8180): Max retries exceeded with url: /realms/idlab/protocol/openid-connect/token (Caused by ProxyError('"'"'Unable to connect to proxy'"'"', OSError('"'"'Tunnel connection failed: 407 Proxy Authentication Required'"'"')))' detail=ProxyError
```

and Squid's access log shows the refusal (native Squid format: time as epoch seconds, elapsed ms, client, result/status, bytes, method, URL, user, hierarchy/peer, content type):

```
1792571177.594      0 172.30.183.3 TCP_DENIED/407 3413 CONNECT keycloak:8180 - HIER_NONE/- text/html
```

`TCP_DENIED/407` with user `-` means the request carried no credentials. `HIER_NONE/-` means Squid never contacted Keycloak. (`date -u -d @1792571177.594` gives `2026-10-21 08:26:17`.)

How customers describe it: *"SSO broke overnight, but only on our app servers; Keycloak and our browsers are fine."* Or, from the app team: *"The IdP is refusing our token requests."* It isn't: the requests never reach it.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  proxy-auth-required            broken   auth.conf: auth_param basic program /usr/local/squid/libexec/basic_ncsa_auth /tmp/squid-passwd auth_param basic realm identity-lab egress proxy acl egress_users proxy_auth REQUIRED http_access deny !egress_users (the RP has no proxy credentials)

# The app's log: which call failed, and the proxy's answer
docker compose logs oidc-rp-egress | grep oidc_login_failed

# The proxy's access log: who was refused, for what
docker compose logs squid | grep -E 'TCP_DENIED(_ABORTED)?/407'
#  ... 172.30.183.3 TCP_DENIED/407 3413 CONNECT keycloak:8180 - HIER_NONE/- text/html

# The app's proxy settings, as its process sees them
docker compose exec oidc-rp-egress printenv HTTPS_PROXY NO_PROXY
#  http://squid:3128
#  localhost,127.0.0.1
```

Then ask the proxy directly, from the app's container (the same network path), and read the headers of its answer. `Proxy-Authenticate` names the authentication schemes the proxy will accept:

```bash
docker compose exec oidc-rp-egress python -c "
import socket
s = socket.create_connection(('squid', 3128))
s.sendall(b'CONNECT keycloak:8180 HTTP/1.1\r\nHost: keycloak:8180\r\n\r\n')
print(s.recv(65536).decode(errors='replace').split('\r\n\r\n')[0])"
#  HTTP/1.1 407 Proxy Authentication Required
#  Server: squid/7.7
#  Mime-Version: 1.0
#  Date: Wed, 21 Oct 2026 08:26:31 GMT
#  Content-Type: text/html;charset=utf-8
#  Content-Length: 3033
#  X-Squid-Error: ERR_CACHE_ACCESS_DENIED 0
#  Content-Language: en
#  Proxy-Authenticate: Basic realm="identity-lab egress proxy"
#  Cache-Status: squid
#  Via: 1.1 squid (squid/7.7)
#  Connection: keep-alive
```

Finally, show that credentials fix it. The password goes in on stdin and only the status comes back, so it isn't in your shell history, the process list or the output:

```bash
grep '^EGRESS_PROXY_PASSWORD=' .env | cut -d= -f2- | tr -d '\n' | docker compose exec -T oidc-rp-egress python -c '
import sys, urllib.parse, requests
proxy = "http://egress-svc:%s@squid:3128" % urllib.parse.quote(sys.stdin.read(), safe="")
r = requests.get("https://keycloak:8180/realms/idlab", proxies={"https": proxy}, timeout=5)
print("status", r.status_code)'
#  status 200
```

Squid logs that one with the username, never the password:

```
1792571192.055     34 172.30.183.3 TCP_TUNNEL/200 9936 CONNECT keycloak:8180 egress-svc HIER_DIRECT/172.18.0.2 -
```

## Diagnosis

1. **407, not 401.** A `401 Unauthorized` comes from the server you're talking to (here it would be Keycloak, for a wrong client secret). A `407 Proxy Authentication Required` comes from a **proxy** on the way and has nothing to do with the IdP. Python's requests reports it as `ProxyError ... Tunnel connection failed: 407`. Java reports `Unable to tunnel through proxy. Proxy returns "HTTP/1.1 407 Proxy Authentication Required"`, and curl reports `CONNECT tunnel failed, response 407`.
2. **Is it the proxy or the app?** If the same app works without the proxy (here, the direct RP on `:8182`) or the same request works with credentials (above), the proxy's policy changed, not the app or the IdP.
3. **Which authentication scheme?** Read `Proxy-Authenticate` in the 407:
   - `Basic realm="..."`: username and password, sent base64-encoded (not encrypted) on every request to the proxy. Most HTTP clients support it, including Python's requests, curl and Java (with `jdk.http.auth.tunneling.disabledSchemes` cleared).
   - `NTLM` or `Negotiate` (Kerberos, or NTLM inside SPNEGO): the usual choice for corporate proxies tied to Active Directory, because browsers on domain-joined machines answer them with the logged-in user and nobody types a password. **This lab's Squid only offers Basic, so the following isn't reproduced here; it is what these schemes typically look like.** The proxy's access log shows `TCP_DENIED/407` entries that are part of the normal handshake: one with no user for NTLM's first round trip, sometimes a second during the challenge, then the tunnel with a user such as `CORP\svc-app` or `svc-app@CORP.EXAMPLE`. So a few 407s per connection are normal for NTLM and Negotiate. A 407 that is **never** followed by a success for that client is the failure. Many server-side clients can't do either scheme at all. Python's requests and plain Java `HttpClient` don't support NTLM or Kerberos to a proxy without extra libraries, so they fail with the same 407 even when a browser on the same server works. For Kerberos, also check the service's keytab, the clock (Kerberos allows about 5 minutes of skew), and that the proxy is addressed by the name its service principal (`HTTP/proxy.corp.example`) was issued for, not by IP.
4. **Credentials in `HTTPS_PROXY` leak.** The common quick fix is `HTTPS_PROXY=http://user:password@proxy:3128`. That puts the password in every place the environment shows up: `docker inspect`, `docker compose config`, `/proc/<pid>/environ`, `printenv` in a support session, CI job logs, crash reports, and sometimes the client's own error messages. Characters such as `@`, `:` or `%` in the password also need URL-encoding, or the URL silently means something else. Prefer an exemption by source network or service identity (below), or credentials read from a secret store by the client, kept out of the URL.
5. **Was anything else changed at the same time?** A 403 instead of a 407 means the proxy did identify you (or doesn't care who you are) and its policy refuses the destination. That's runbook 12.

**Root cause, in one sentence for the customer:** the egress proxy was changed to require authentication, and the application servers' calls to the identity provider have no proxy credentials, so the proxy refuses to connect them (407) and every login on those apps fails after the password; the identity provider itself is healthy.

## Fix

1. Restore the access the app had. In the lab:
   ```bash
   scripts/fix.sh proxy-auth-required
   ```
   By hand, that's emptying `.state/squid/auth.conf` again (the default is in `squid/defaults/auth.conf`), then:
   ```bash
   docker compose exec squid squid -k parse -f /etc/squid/squid.conf         # check before applying
   docker compose exec squid squid -k reconfigure -f /etc/squid/squid.conf   # no restart
   ```
2. Verify: log in at https://LAB_HOST:8186/ in a new private window. Squid logs `TCP_TUNNEL/200 ... CONNECT keycloak:8180`, and `scripts/status.sh` shows `healthy`.

In a real deployment, the lasting fix is one of:

- **Exempt the app servers from authentication by source address** (as this lab's healthy configuration does with `egress_clients`), limited to the IdP's address if the policy needs that.
- **A service account for the app on the proxy,** with the password supplied from the app's secret store and rotated on a schedule both teams know about.
- **For NTLM or Kerberos-only proxies,** a client that supports them, or a local authenticating relay on the app server (Cntlm or Px, for example) that the app points `HTTPS_PROXY` at.

Don't turn off authentication for everyone to make one app work, and don't paste the account's password into `HTTPS_PROXY` in a shared config file.

## Prevention

- **Announce proxy policy changes to app owners,** with the list of server networks and service accounts that will lose access, and a test window.
- **Monitor the login, not just the components.** Keycloak, the app and the proxy were all "up". A synthetic login through each app catches this in minutes.
- **Alert on 407s from server networks.** Browsers on staff machines answer 407s by themselves; servers don't, so a sudden run of `TCP_DENIED/407` from a server subnet is almost always an outage.
- **Track service-account proxy passwords** like any other credential: expiry dates, owners, rotation runbooks.

## Questions I'd ask the customer

1. Does the error mention `407` or `Proxy Authentication Required`, or a 401 or `invalid_client` from the IdP?
2. Do all apps on these servers fail, or only those that call out through the proxy? Does it work from a server that doesn't use the proxy?
3. Did anything change on the proxy recently: authentication turned on, a new authentication scheme (NTLM, Kerberos), a password expiry or rotation?
4. How are the app servers configured to reach the proxy: `HTTPS_PROXY` and `NO_PROXY` variables, Java system properties (`https.proxyHost`), a setting in the app itself, or a **PAC file or WPAD**? Browsers usually follow a PAC file (often found through WPAD, `http://wpad.<domain>/wpad.dat`) and authenticate with the logged-in user's Kerberos or NTLM credentials. Server-side services usually ignore PAC and WPAD and use their own settings. So "it works in a browser on the same server" doesn't show that the service has a working path.
5. Which `Proxy-Authenticate` schemes does the proxy offer, and which does the app's HTTP client support?
6. Can you send the proxy's access log lines for the app server's address at the time of a failed login?
