# 10 · Reverse proxy: Keycloak's headers too large for the proxy

| | |
|---|---|
| **Protocol** | HTTP(S) through an nginx reverse proxy in front of Keycloak. nginx reads each upstream response's status line and headers into one buffer (`proxy_buffer_size`); Keycloak's headers carry its session cookies. |
| **Blast radius** | Every login through that proxy, SAML and OIDC, for every user, at the first Keycloak page. A variant hits only *some* users: those whose cookies or requests are bigger (more groups or roles in a token, a long redirect URI, many apps on one session). Keycloak reached directly (`:8180`) is fine. |
| **Typical trigger** | Proxy buffers reduced "to save memory" or copied from a config written for a small API; or Keycloak's cookies grew (a Keycloak upgrade, more claims, a new client with a long redirect URI) past a limit that used to be enough. |
| **Lab** | `scripts/break.sh proxy-header-too-large` · `scripts/fix.sh proxy-header-too-large` (changes `proxy_buffer_size 16k;` to `1k` in `.state/proxy/kc-buffers.conf` and reloads nginx; Keycloak is not touched) |

## Symptom

Go to https://LAB_HOST:8184/ (SAML) or https://LAB_HOST:8185/ (OIDC) and click **Log in**. Where Keycloak's login page should be, at a `https://LAB_HOST:8183/realms/idlab/...` URL, nginx answers instead:

```
502 Bad Gateway
nginx
```

The proxy's error log says exactly what happened:

```
2026/10/20 17:50:45 [error] 3115#3115: *670 upstream sent too big header while reading response header from upstream, client: 172.30.182.1, server: , request: "GET /realms/idlab/protocol/saml?SAMLRequest=***&RelayState=…&Signature=***&SigAlg=… HTTP/1.1", upstream: "https://172.30.182.2:8180/realms/idlab/protocol/saml?SAMLRequest=***&RelayState=…&Signature=***
2026/10/20 17:50:47 [error] 3115#3115: *675 upstream sent too big header while reading response header from upstream, client: 172.30.182.1, server: , request: "GET /realms/idlab/protocol/openid-connect/auth?response_type=code&client_id=oidc-rp-proxied&redirect_uri=https%3A%2F%2Fidlab.home%3A8185%2Fauth%2Fcallback&scope=openid+email+profile&state=***&nonce=***&code_challenge=***&code_challenge_method=S256 HTTP/1.1", upstream: "https://172.30.182.2:8180/realms/idlab/protocol/openid-connect/auth?...", host: "idlab.home:8183", referrer: "https://idlab.home:8185/"
```

(The proxy masks one-time login values such as the SAML message, its signature, the state, nonce and PKCE challenge as `***`; other long values are shortened here to `…`.) In the access log the request did reach Keycloak and came back fast, but nginx turned it into a 502:

```
172.30.182.1 "GET /realms/idlab/protocol/openid-connect/auth?response_type=code&client_id=oidc-rp-proxied&... HTTP/1.1" 502 552 host=idlab.home:8183 upstream=172.30.182.2:8180 upstream_status=502 request_time=0.013 upstream_time=0.013
```

**Keycloak logs nothing.** From its side the request succeeded: it built the login page, set its cookies and sent the response. The proxy discarded it.

How customers describe it: *"After the proxy change, SSO gives Bad Gateway,"* or for the variant, *"only some users get Bad Gateway, always the same ones."*

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  proxy-header-too-large         broken   kc-buffers.conf: proxy_buffer_size 1k; proxy_buffers 8 16k; proxy_busy_buffers_size 32k; (Keycloak's login page sends about 2 KB of headers)

# The proxy: the decisive line
docker compose logs proxy | grep 'too big header'

# The proxy's buffers for that route
docker compose exec proxy nginx -T 2>/dev/null | grep -E 'proxy_buffer'
```

Then measure how big Keycloak's headers actually are, without the proxy in the way or with a healthy route. `curl -w '%{size_header}'` gives the total, and the individual header lines show what takes the space. Measured in this lab, for a login through the proxy:

```
login page: header bytes 2058, status 200
after password POST: header bytes 1577, status 302
--- largest headers on the login page (name: bytes)
Set-Cookie: 1143
Set-Cookie: 256
Set-Cookie: 162
Content-Security-Policy: 86
Strict-Transport-Security: 63
```

The login page is the biggest response, at about 2 KB, and one cookie (Keycloak's `KC_RESTART`, which holds the login request so it can be restarted) is more than half of it. That's why this fails **before** the login form, not after the password.

```bash
# The login page's response headers, directly from Keycloak (no proxy). An
# authorisation request like the app's; the code_challenge is any valid value.
curl -sS -o /dev/null -D - --cacert certs/ca.crt -G \
  "https://LAB_HOST:8180/realms/idlab/protocol/openid-connect/auth" \
  --data-urlencode client_id=oidc-rp --data-urlencode response_type=code \
  --data-urlencode scope=openid --data-urlencode redirect_uri=https://LAB_HOST:8182/auth/callback \
  --data-urlencode code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM \
  --data-urlencode code_challenge_method=S256 \
  | tr -d '\r' | awk 'tolower($1)=="set-cookie:" {split($2,a,"="); print length($0) "\t" a[1]}'
#  255     AUTH_SESSION_ID
#  159     KC_AUTH_SESSION_HASH
#  1104    KC_RESTART
```

(Directly, curl talks HTTP/2 to Keycloak, which sends header names in lower case; hence `tolower`. The cookie is a little shorter than through the proxy because this client's redirect URI is shorter.)

## Diagnosis

1. **502 with `upstream sent too big header`.** The upstream is reachable and answered: the route, port and TLS are fine (compare runbook 06, where the 502 has a different error line). The *headers* of its answer didn't fit in `proxy_buffer_size`.
2. **Which buffer?** nginx has several, for different directions, and each fails differently. All of these were captured with nginx 1.30.6:

   | What's too big | Directive (default) | What the client sees | Proxy log |
   |---|---|---|---|
   | The **upstream's response headers** (Keycloak's `Set-Cookie`, a long `Location`) | `proxy_buffer_size` (4k or 8k, one memory page) | `502 Bad Gateway` | `[error] upstream sent too big header while reading response header from upstream` **(this scenario)** |
   | A **request header from the browser** (a big `Cookie:` header, many cookies on one domain) | `large_client_header_buffers` (4 8k) | `400 Bad Request`, page title `400 Request Header Or Cookie Too Large` | `[info] client sent too long header line: "Cookie: KEYCLOAK_IDENTITY=..." while reading client request headers`. **Logged at `info` only**, so with the usual `error_log ... error` (or `notice`, as here) it doesn't appear at all |
   | A **request body** (a big SAML Response POSTed to an SP's ACS) | `client_max_body_size` (1m) | `413 Request Entity Too Large` | `[error] client intended to send too large body: 12013 bytes` |

   The 400 and 413 rows were reproduced in a throwaway nginx with `large_client_header_buffers 4 1k` and `client_max_body_size 4k`.
3. **Does it hit everyone or some users?** If everyone fails at the same page, the limit is below what Keycloak always sends, usually after a proxy change. If only some users fail, the limit is close to the edge and their requests are bigger: compare a failing user's cookies and token size with a working user's. Users in many groups, with many roles mapped into tokens, or with sessions in several apps, are the usual ones.
4. **Why not the app?** The error is from the proxy, at the IdP's URL, and the IdP has no matching error. Nothing in the SAML or OIDC configuration changed.

**Root cause, in one sentence for the customer:** the reverse proxy's buffer for response headers from Keycloak was reduced to 1 KB, but Keycloak's login page sends about 2 KB of headers (mostly its session cookies), so the proxy rejects every login page with 502 Bad Gateway even though Keycloak answered normally.

## Fix

1. Give the route enough room for the headers, with headroom. In the lab:
   ```bash
   scripts/fix.sh proxy-header-too-large
   ```
   which restores
   ```nginx
   proxy_buffer_size       16k;
   proxy_buffers           8 16k;
   proxy_busy_buffers_size 32k;
   ```
   then `nginx -t` and `nginx -s reload`. `proxy_buffer_size` is the one that matters for headers. Raise `proxy_busy_buffers_size` with it, or `nginx -t` refuses the config:
   ```
   nginx: [emerg] "proxy_busy_buffers_size" must be equal to or greater than the maximum of the value of "proxy_buffer_size" and one of the "proxy_buffers" in /etc/nginx/nginx.conf:2
   ```
2. For the client-side variants: raise `large_client_header_buffers` for big cookies, or `client_max_body_size` on the SP's route for big SAML POSTs. Raise them only on the routes that need it.
3. If cookies or tokens keep growing, shrink them at the source: fewer roles and groups mapped into tokens, shorter redirect URIs, fewer apps sharing one cookie domain.
4. Verify: the login page loads through the proxy, logins complete, the proxy logs no new `too big header` lines, and `scripts/status.sh` shows `healthy`.

## Prevention

- **Set the IdP route's buffers deliberately,** with the reason next to them. Measure Keycloak's largest response headers (above) and allow several times that.
- **Keep the proxy's `error_log` at a level where these lines appear,** and know that the oversized *request* header case is `info` only: you won't see it at `error`. Turn the level up on the IdP route while investigating.
- **Test logins through the proxy after any proxy change,** and after Keycloak upgrades and changes to token mappers or clients: they change cookie sizes.
- **Watch token and cookie sizes** as part of identity changes: adding every group to a token is the most common way they grow.

## Questions I'd ask the customer

1. At which step does the error appear: before the login page, after the password, or when the app receives the login? Which URL is in the address bar?
2. Is it every user, or only some? What do the affected users have in common (many groups, many apps, a particular browser profile)?
3. What's the status code and the error page title: 502, `400 Request Header Or Cookie Too Large`, or 413?
4. What changed recently: the proxy's buffer or size settings, the IdP version, token mappers, new clients?
5. Can you send the proxy's error log lines for a failing request? If there are none, at which level does the proxy log?
6. How large are the IdP's response headers and the user's cookies? (A HAR file from the browser shows both; remove cookie values before sending it.)
