# 12 · Egress proxy: 403 Forbidden by the proxy's policy

| | |
|---|---|
| **Protocol** | HTTPS from an app server to the IdP through a forward ("egress") proxy, as `CONNECT keycloak:8180`. Here, the OIDC RP's back channel: discovery, token, userinfo and JWKS. |
| **Blast radius** | Every client of that proxy whose traffic matches the rule. Here, that's every login on the OIDC RP at `https://LAB_HOST:8186`. Browsers and apps that don't use the proxy (the direct OIDC RP on `:8182`) keep working, and Keycloak sees nothing. |
| **Typical trigger** | A URL filtering or category update, a new "deny anything uncategorised" rule, an allowlist that was rebuilt without the IdP, or the IdP moving to a new hostname or IP range that the allowlist doesn't cover yet. |
| **Lab** | `scripts/break.sh proxy-policy-block` · `scripts/fix.sh proxy-policy-block` (adds a `dstdomain` deny rule for `keycloak` to `.state/squid/policy.conf` and runs `squid -k reconfigure`) |

## Symptom

Go to https://LAB_HOST:8186/, click **Log in with OIDC** and sign in as `alice`. Back at the app, it shows **OIDC login failed**:

```
HTTPSConnectionPool(host='keycloak', port=8180): Max retries exceeded with url: /realms/idlab/protocol/openid-connect/token (Caused by ProxyError('Unable to connect to proxy', OSError('Tunnel connection failed: 403 Forbidden')))
Error code   backchannel_failed
Detail       ProxyError
```

As in runbook 11, the user signed in to Keycloak but the app couldn't redeem the code. If the app has restarted since its last login, the failure comes straight after **Log in**, at `/.well-known/openid-configuration`.

The app's log:

```
2026-10-21 08:30:30,538 WARNING oidc-rp event=oidc_login_failed reason=backchannel_failed error='HTTPSConnectionPool(host='"'"'keycloak'"'"', port=8180): Max retries exceeded with url: /realms/idlab/protocol/openid-connect/token (Caused by ProxyError('"'"'Unable to connect to proxy'"'"', OSError('"'"'Tunnel connection failed: 403 Forbidden'"'"')))' detail=ProxyError
```

Squid's access log:

```
1792571430.538      0 172.30.183.3 TCP_DENIED/403 3331 CONNECT keycloak:8180 - HIER_NONE/- text/html
```

`TCP_DENIED/403` with `HIER_NONE/-`: refused by the proxy's own rules, without contacting Keycloak, and answered in 0 ms. Sometimes the same refusal is logged as

```
1792574017.903      2 172.30.183.3 TCP_DENIED_ABORTED/403 293 CONNECT keycloak:8180 - HIER_NONE/- text/html
```

`_ABORTED` means the client hung up before Squid had sent the whole error page (293 bytes instead of 3331). Python's requests reads the status line of a refused CONNECT and closes the connection, so whether Squid finishes writing first is a race. It's the same refusal; search for both forms.

How customers describe it: *"The IdP is blocking us."* It isn't: the IdP never received the request.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  proxy-policy-block             broken   policy.conf: acl blocked_sites dstdomain keycloak .unapproved.example http_access deny CONNECT blocked_sites (keycloak is the IdP the RP needs)

# The proxy's access log: refusals for the IdP
docker compose logs squid | grep -E 'TCP_DENIED(_ABORTED)?/403 .* keycloak'

# Ask the proxy yourself, from the app's container, and read its answer
docker compose exec oidc-rp-egress python -c "
import socket
s = socket.create_connection(('squid', 3128))
s.sendall(b'CONNECT keycloak:8180 HTTP/1.1\r\nHost: keycloak:8180\r\n\r\n')
print(s.recv(65536).decode(errors='replace').split('\r\n\r\n')[0])"
#  HTTP/1.1 403 Forbidden
#  Server: squid/7.7
#  Mime-Version: 1.0
#  Date: Wed, 21 Oct 2026 08:30:31 GMT
#  Content-Type: text/html;charset=utf-8
#  Content-Length: 3038
#  X-Squid-Error: ERR_ACCESS_DENIED 0
#  Content-Language: en
#  Cache-Status: squid
#  Via: 1.1 squid (squid/7.7)
#  Connection: keep-alive
```

The body of that 403 is Squid's error page. Its text is what a browser user would see. A server-side client like the app's never shows it:

```
ERROR
The requested URL could not be retrieved
The following error was encountered while trying to retrieve the URL: keycloak:8180
Access Denied.
Access control configuration prevents your request from being allowed at this time. Please contact your service provider if you feel this is incorrect.
Generated Wed, 21 Oct 2026 08:30:39 GMT by squid (squid/7.7)
```

`ERR_ACCESS_DENIED` says an `http_access` rule refused it, but not which one. `squid -k parse` prints every line it reads, included files in place, so it lists the rules in the order Squid applies them (first match wins):

```bash
docker compose exec squid squid -k parse -f /etc/squid/squid.conf 2>&1 | grep -E 'Processing: (acl|http_access)'
#  2026/10/21 08:31:47| Processing: acl egress_clients src 172.30.183.0/24
#  2026/10/21 08:31:47| Processing: acl SSL_ports port 8180
#  2026/10/21 08:31:47| Processing: acl CONNECT method CONNECT
#  2026/10/21 08:31:47| Processing: http_access deny CONNECT !SSL_ports
#  2026/10/21 08:31:47| Processing: acl blocked_sites dstdomain keycloak .unapproved.example
#  2026/10/21 08:31:47| Processing: http_access deny CONNECT blocked_sites
#  2026/10/21 08:31:47| Processing: http_access allow egress_clients
#  2026/10/21 08:31:47| Processing: http_access deny all
```

The `deny CONNECT blocked_sites` line comes before `allow egress_clients`, so the app servers never get to the allow.

## Diagnosis

1. **403 from the proxy, or from the IdP?** `Tunnel connection failed: 403` (or curl's `CONNECT tunnel failed, response 403`) means the **proxy** refused to open the tunnel; the request never reached the IdP. A 403 from the IdP itself would come back inside a working tunnel, with Keycloak's own error body, and the proxy would log `TCP_TUNNEL/200`.
2. **403 vs 407.** 407 (runbook 11) means "tell me who you are". 403 means "I know enough, and the answer is no", whether or not the proxy asked for a login.
3. **Which rule?** In Squid, `ERR_ACCESS_DENIED` and `TCP_DENIED/403` come from `http_access deny`. Commercial proxies and secure web gateways usually show the category or policy name on their block page, or in their logs (for example *"Uncategorized"*, *"Newly registered domain"*). Ask the proxy team for the log entry for the app server's address at the time of a failed login.
4. **Name or address?** A rule can match the name in the CONNECT (Squid's `dstdomain`, as here) or the resolved address (`dst`). Address rules catch an IdP that has moved behind a CDN or to a new IP range even though its name didn't change. Name rules miss an IdP that's reached by a different name (an alias, or an internal name versus a public one).
5. **If the proxy also inspects TLS, the 403 can look like a certificate error.** With TLS interception turned on, Squid answers a denied CONNECT with `200 Connection established`, intercepts the tunnel and serves the 403 page inside TLS that it signs itself. A client that doesn't trust the proxy's CA then reports a certificate error, not a 403. This was captured in the lab while building this scenario, with interception switched on:

   ```
   1792571365.606     14 172.30.183.3 TCP_DENIED/200 0 CONNECT keycloak:8180 - HIER_NONE/- -
   ```
   ```
   ... (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain (_ssl.c:1032)')))
   ```

   `TCP_DENIED` with status `/200` is the giveaway: the proxy denied it, then served the denial over its own TLS. Runbook 13 covers interception itself.

**Root cause, in one sentence for the customer:** a filtering rule on the egress proxy refuses connections to the identity provider's address, so the application servers can't complete any login (the proxy answers 403 Forbidden), while the identity provider itself is healthy.

## Fix

1. Remove or narrow the rule. In the lab:
   ```bash
   scripts/fix.sh proxy-policy-block
   ```
   By hand, empty `.state/squid/policy.conf` (default: `squid/defaults/policy.conf`), then:
   ```bash
   docker compose exec squid squid -k parse -f /etc/squid/squid.conf
   docker compose exec squid squid -k reconfigure -f /etc/squid/squid.conf
   ```
2. Verify: a login at https://LAB_HOST:8186/ works, Squid logs `TCP_TUNNEL/200 ... CONNECT keycloak:8180`, and `scripts/status.sh` shows `healthy`.

In a real deployment, ask for an explicit allow rule for the IdP's hostnames (all of them: login, token, JWKS, and any CDN host for its pages) placed **before** the category or blocklist rules, rather than taking the IdP out of a category.

## Prevention

- **Keep an allowlist of identity endpoints** your apps depend on, owned by both teams, and test against it whenever the proxy's policy or categories change.
- **Give each deny rule its own error page** (Squid's `deny_info`) or a named policy, so a 403 says which rule fired.
- **Monitor logins through the proxy path,** not only the IdP and the apps.
- **Ask the IdP vendor for its published endpoints and IP ranges,** and subscribe to changes, if the policy is address-based.

## Questions I'd ask the customer

1. Does the error say `Tunnel connection failed: 403` (or similar), or does a 403 come from the IdP itself?
2. Which apps and servers are affected? Do apps that don't use the proxy still work?
3. Did the proxy's filtering policy, categories or allowlists change recently? Did the IdP's hostnames or IP addresses change?
4. Can you send the proxy's log entry for the app server's address at the time of a failed login, including the rule or category that matched?
5. How does the app server choose its proxy: `HTTPS_PROXY` and `NO_PROXY`, Java system properties, an app setting, or a **PAC file or WPAD**? Browsers usually follow the PAC file, which may send the IdP `DIRECT` or to a different proxy with a different policy, while services usually ignore PAC and WPAD. So a browser test on the same server can succeed while the service is blocked.
6. Does the proxy inspect TLS? If so, could some of the "certificate" errors you've seen be blocks in disguise?
