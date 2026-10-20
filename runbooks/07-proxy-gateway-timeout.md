# 07 · Reverse proxy: 504 Gateway Time-out

| | |
|---|---|
| **Protocol** | HTTP(S) through an nginx reverse proxy, on the OIDC login callback (`/auth/callback`), the step where the app redeems the authorisation code with Keycloak. |
| **Blast radius** | Requests on that proxy route that take longer than the proxy is willing to wait. Here: every login through `https://LAB_HOST:8185`. Fast pages on the same app still load. The direct path (`:8182`) is a separate container and isn't slowed. |
| **Typical trigger** | Something behind the app got slower (a database, an API, the IdP's token endpoint, DNS), or a proxy timeout was tightened below how long a legitimate request takes. Often intermittent: it fails under load and works when someone tries it by hand. |
| **Lab** | `scripts/break.sh proxy-gateway-timeout` · `scripts/fix.sh proxy-gateway-timeout` (makes the app behind the proxy take an extra 10 s on its callback, via `.state/oidc-rp-proxied/callback-delay`; the proxy keeps its 5 s `proxy_read_timeout`) |

## Symptom

Go to https://LAB_HOST:8185/, click **Log in with OIDC** and sign in as `alice`. The Keycloak login works. About **5 seconds** after you submit the password, nginx answers instead of the app:

```
504 Gateway Time-out
nginx
```

504 means **the proxy reached the app and sent the request, but gave up waiting for the answer**. Unlike a 502 (runbook 06), the app was there and accepted the request. It was just slower than the proxy's timeout.

The proxy's error log:

```
2026/10/20 17:39:43 [error] 1906#1906: *387 upstream timed out (110: Operation timed out) while reading response header from upstream, client: 172.30.182.1, server: , request: "GET /auth/callback?state=…&session_state=…&iss=https%3A%2F%2Fidlab.home%3A8183%2Frealms%2Fidlab&code=… HTTP/1.1", upstream: "https://172.30.182.3:8182/auth/callback?…", host: "idlab.home:8185"
```

and its access log, with the timing that gives it away:

```
172.30.182.1 "GET /auth/callback?state=…&code=… HTTP/1.1" 504 562 host=idlab.home:8185 upstream=172.30.182.3:8182 upstream_status=504 request_time=5.005 upstream_time=5.005
```

(Authorisation codes and state values are shortened to `…` here. The real log lines contain them in full; see Prevention.)

**The app didn't fail.** It carried on after the proxy had given up, redeemed the code and logged a successful login, five seconds after the user was shown the error:

```
2026-10-20 17:39:48,883 INFO oidc-rp event=oidc_login_ok sub=83eb3a89-90f1-4e3c-9cf3-dcf709a325fb email=alice@idlab.example iss=https://idlab.home:8183/realms/idlab elapsed=10.10s
172.30.182.10 - - [20/Oct/2026:17:39:48 +0000] "GET /auth/callback?state=…&code=… HTTP/1.1" 302 199 "-" "Mozilla/5.0 (X11; Linux x86_64) ..."
```

**Refreshing the error page makes it worse.** The browser sends the same callback, with the same, now used, authorisation code. The user gets another 504 after 5 seconds. Behind it, Keycloak refuses the code and the app logs a failure that nobody sees:

```
2026-10-20 17:40:35,623 WARN  [org.keycloak.events] (executor-thread-13) type="CODE_TO_TOKEN_ERROR", realmId="bc6eaf0d-...", realmName="idlab", clientId="oidc-rp-proxied", userId="null", sessionId="aQzZ70SF9F9qQj-QPC8EOGHM", ipAddress="172.30.182.3", error="invalid_code", grant_type="authorization_code", code_id="aQzZ70SF9F9qQj-QPC8EOGHM", client_auth_method="client-secret"
2026-10-20 17:40:35,638 WARNING oidc-rp event=oidc_login_failed reason=invalid_grant error='Code not valid' detail=OAuthError
```

A healthy login through the proxy, for comparison:

```
2026-10-20 17:39:29,102 INFO oidc-rp event=oidc_login_ok sub=83eb3a89-... email=alice@idlab.example iss=https://idlab.home:8183/realms/idlab elapsed=0.05s
```

How customers describe it: *"SSO is timing out,"* or *"login hangs and then errors, but if I try again later it works."* Because the IdP part of the login works, it's easy to blame the IdP.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  proxy-gateway-timeout          broken   oidc-rp-proxied callback takes an extra 10s (proxy_read_timeout 5s)

# The proxy: which requests timed out, and after how long
docker compose logs proxy | grep 'upstream timed out'
docker compose logs proxy | grep -E '" 504 ' | grep -o 'request_time=[0-9.]* upstream_time=[0-9.]*'
#  request_time=5.005 upstream_time=5.005

# The proxy's timeout on that route
docker compose exec proxy nginx -T 2>/dev/null | grep -nE 'listen 818|proxy_read_timeout'
#  115:        listen 8185 ssl;
#  120:            proxy_read_timeout 5s;

# The app: how long the same request really took
docker compose logs oidc-rp-proxied | grep -E 'event=oidc_login_(ok|failed)'
#  ... event=oidc_login_ok ... elapsed=10.10s
```

Line the two up. A `request_time` that equals the timeout exactly (5.005 against `proxy_read_timeout 5s`) means nginx stopped waiting; it says nothing about how long the app needed. The app's own timing (here `elapsed=10.10s`) does.

## Diagnosis

1. **504, not 502.** The proxy connected and sent the request (`while reading response header from upstream`), so the route, the port and TLS to the app are all fine. Only the time is wrong.
2. **Which timeout?** nginx has three for upstreams, each 60 s by default:
   - `proxy_connect_timeout`: establishing the connection.
   - `proxy_send_timeout`: between two writes of the request to the upstream.
   - `proxy_read_timeout`: between two reads of the response. The usual one, and this one: the app sent nothing for 5 s.

   The error line says which: `while connecting to upstream` or `while reading response header from upstream`.
3. **Is the app slow, or the timeout too short?** Compare the app's normal time for the request (here 0.05 s) with now (10 s). A request that used to be fast and is now slow points at whatever the app waits on: its database, an API, the IdP's token endpoint. A request that has always been slow (a big export, a report) and a timeout someone recently lowered point at the proxy change.
4. **Check whether the app finished.** Here it did: `oidc_login_ok` five seconds after the 504. With a timeout in front of it, work isn't cancelled, only the answer is lost. For a login, that means a used authorisation code and a session the user never received. For a form or a payment, it can mean the action happened and the user tries again.
5. **Retries confuse the picture.** A refresh of the callback URL reuses the code, so the logs fill with `invalid_code` / `Code not valid` after the first timeout. They're a consequence, not the cause. Look for the first failure for that user.

**Root cause, in one sentence for the customer:** the app behind the reverse proxy now takes about 10 seconds to complete the login callback, while the proxy waits at most 5 seconds for it, so the proxy returns 504 Gateway Time-out even though the app completes the login afterwards.

## Fix

1. **Fix the slowness first.** In the lab:
   ```bash
   scripts/fix.sh proxy-gateway-timeout
   ```
   In real life, find what the app is waiting on (its logs and traces around the slow request) and fix that.
2. **Raise the timeout only for a request that is legitimately slow,** and only on that location, not for the whole site:
   ```nginx
   location /reports/ {
       proxy_read_timeout 120s;
       ...
   }
   ```
   then `nginx -t` and `nginx -s reload`. A long timeout everywhere just holds connections open for longer when something is stuck.
3. Verify: a login through `:8185` lands on the app's success page, the app logs `elapsed=` well under a second, the proxy logs `200`/`302` with a small `upstream_time`, and `scripts/status.sh` shows `healthy`.

## Prevention

- **Know your slowest legitimate request** for each route, and set proxy timeouts per location with headroom above it, not one global value.
- **Log timing on both sides:** `$request_time` and `$upstream_response_time` at the proxy, and request duration in the app. Alert on their high percentiles, not just on 504 counts; latency creeps up before it crosses a timeout.
- **Timeouts should get shorter from the outside in** only with care: if a load balancer in front of nginx gives up at 30 s while nginx waits 60 s, users see the load balancer's error, not nginx's, and nginx's log shows the client went away instead.
- **Access logs contain authorisation codes** in the callback's query string, as above. They're single use and short-lived, but treat proxy logs as sensitive, or use a log format that drops `$args` on callback paths.

## Questions I'd ask the customer

1. Is it a 504 (gateway timeout) or a 502? What text and branding does the error page have?
2. How long after submitting the password does the error appear? Is it always the same number of seconds?
3. Does the user turn out to be logged in anyway if they open the app again afterwards?
4. Is it every login, or only at busy times? Does it happen to every user?
5. What changed recently: the proxy's or load balancer's timeouts, the app's infrastructure, its database, the network to the IdP?
6. Can you send the proxy's access log lines with `request_time` and `upstream_response_time` for a failing request, and the app's log for the same time?
