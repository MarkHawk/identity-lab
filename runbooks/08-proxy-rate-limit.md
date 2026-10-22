# 08 · Reverse proxy: 429 Too Many Requests

| | |
|---|---|
| **Protocol** | HTTP(S) through an nginx reverse proxy in front of Keycloak, with a request rate limit (`limit_req`) on Keycloak's `/realms/` endpoints. |
| **Blast radius** | Everyone whose requests the proxy counts as coming from the same client address. Behind a NAT, a corporate proxy or another load balancer that's often **every user at once**. In the lab every browser request reaches nginx from the Docker gateway, `172.30.182.1`, so all logins share one limit. The direct path (`:8180`) has no limit. |
| **Typical trigger** | A rate limit tightened to slow down password guessing or a noisy client, without measuring how many requests a normal login makes; or a limit keyed on the client address after a new load balancer or NAT made all traffic arrive from one address. |
| **Lab** | `scripts/break.sh proxy-rate-limit` · `scripts/fix.sh proxy-rate-limit` (changes `.state/proxy/rate-limit-zone.conf` from `rate=10r/s` to `rate=6r/m`, and `.state/proxy/rate-limit.conf` from `burst=20 nodelay` to no burst, then reloads nginx) |

## Symptom

Go to https://LAB_HOST:8185/, click **Log in with OIDC**. Keycloak's login page loads normally. Sign in as `alice`, and instead of the app you get nginx's error page:

```
429 Too Many Requests
nginx
```

The browser is left on Keycloak's `/realms/idlab/login-actions/authenticate` URL. A minute later it may work once, then fail again.

The proxy's error log names the limit and by how much the request was over it:

```
2026/10/20 17:42:32 [error] 2290#2290: *457 limiting requests, excess: 0.977 by zone "kc_login", client: 172.30.182.1, server: , request: "POST /realms/idlab/login-actions/authenticate?session_code=***&execution=…&client_id=oidc-rp-proxied&tab_id=…&client_data=*** HTTP/1.1", host: "idlab.home:8183"
```

and the access log shows that **Keycloak never saw the request** (`upstream=-`, answered in 0 ms):

```
172.30.182.1 "POST /realms/idlab/login-actions/authenticate?session_code=***&execution=…&client_id=oidc-rp-proxied&tab_id=…&client_data=*** HTTP/1.1" 429 564 host=idlab.home:8183 upstream=- upstream_status=- request_time=0.000 upstream_time=-
```

(The proxy masks the session code and `client_data`, which holds the OAuth state, as `***`; other long values are shortened here to `…`.) Because Keycloak never received these requests, its own log and its admin console's events show nothing wrong.

The response itself, as a client sees it:

```
HTTP/1.1 429 Too Many Requests
Server: nginx
Content-Type: text/html
Connection: keep-alive

<html>
<head><title>429 Too Many Requests</title></head>
<body>
<center><h1>429 Too Many Requests</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

There is **no `Retry-After` header**, and no `X-RateLimit-*` or `RateLimit` header either. nginx's `limit_req` doesn't send any by default. See Diagnosis for what that means for clients.

How customers describe it: *"Login fails with Too Many Requests, but we're not doing anything unusual,"* or *"it works for the first person in the morning and then nobody can log in."*

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  proxy-rate-limit               broken   rate-limit-zone.conf: limit_req_zone $binary_remote_addr zone=kc_login:1m rate=6r/m; (tighter than a login needs) / rate-limit.conf: limit_req zone=kc_login; (no burst allowance)

# The proxy: which zone refused what, and from which client address
docker compose logs proxy | grep 'limiting requests'
docker compose logs proxy | grep -E '" 429 ' | grep -o 'upstream=[^ ]*'
#  upstream=-

# The limit as nginx has it, and where it applies
docker compose exec proxy nginx -T 2>/dev/null | grep -nE 'limit_req|location'
```

### Measure the limit with rate-limit-probe

[rate-limit-probe](https://github.com/MarkHawk/rate-limit-probe) sends a small, slow, capped sequence of GET requests and reports when the 429s start, how long they last and whether the server says when to retry. Install it from a clone:

```bash
git clone https://github.com/MarkHawk/rate-limit-probe.git
cd rate-limit-probe
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Probe an endpoint behind the same limit. Keycloak's discovery document is under `/realms/` and safe to fetch repeatedly. Wait about 15 seconds after a login attempt first, so the probe starts with the limit unused. From the identity-lab directory:

```bash
# LAB_HOST is not localhost: the probe needs --i-am-authorised, and --cacert for the lab's CA
rate-limit-probe https://LAB_HOST:8183/realms/idlab/.well-known/openid-configuration \
  --i-am-authorised --cacert certs/ca.crt

# with LAB_HOST=localhost (CI, Codespaces), only the CA is needed
rate-limit-probe https://localhost:8183/realms/idlab/.well-known/openid-configuration --cacert certs/ca.crt
```

With the scenario broken (output from a real run, `LAB_HOST=idlab.home`; the warning for a non-local host goes to standard error and is left out):

```
rate-limit-probe 0.1.0
Target:   https://idlab.home:8183/realms/idlab/.well-known/openid-configuration (authorised remote host)
Limits:   up to 100 requests, 10/s or slower, one connection, waits up to 60 s
Sent:     8 requests (GET) over 16.2 s

== Timeline ==
  #1       200  0.0 s
  #2       429  0.1 s
                             waited 1 s, to test an early retry
  #3       429  1.1 s        sent early on purpose
                             waited 1 s, backing off: no header said how long
  #4       429  2.1 s
                             waited 2 s, backing off: no header said how long
  #5       429  4.1 s
                             waited 4 s, backing off: no header said how long
  #6       429  8.1 s
                             waited 8 s, backing off: no header said how long
  #7       200  16.1 s
  #8       429  16.2 s

== Findings ==
  INFO  When 429s start  Request 2, 0.1 s in: 1 request was accepted first.
  INFO  Observed limit   1 request, then refused until somewhere between 8.1 s and 16 s after the
                         first request (found by backing off, as no header said).
  WARN  Retry-After      No 429 carried Retry-After, and no other header said when to retry. Clients
                         have to guess.
  INFO  Quota headers    No X-RateLimit or RateLimit headers, so a client cannot see the limit
                         coming.
  INFO  Early retry      A request 1 s after the 429 was refused. With no wait in the headers, the
                         probe cannot tell whether early retries extend the limit.
  PASS  Recovery         Backing off (1, 2, 4, 8 s) worked: accepted again 16 s after the first 429.
  INFO  Reset            After the wait, the full 1 request were available again at once.

== Likely cause ==
  The API sends no Retry-After or rate-limit headers, so a client cannot know how long to wait, and
  a short fixed retry keeps hitting the limit. Here the limit lifted between 8 s and 16 s after the
  first 429.
  Next step:  Give the client exponential back-off with jitter on 429, starting at 1 s and allowing
              at least 16 s. Ask the API owner to send Retry-After.

Verdict: no failures, 1 warning to review (0 FAIL, 0 WARN, 1 PASS, 5 INFO)
```

Read it against the configuration: **1 request accepted, then refused for between 8 and 16 seconds** is exactly `rate=6r/m` with no burst. nginx's limiter is a leaky bucket: 6 a minute means one request every 10 seconds, and without a `burst` nothing may queue or go early. A login needs at least two `/realms/` requests a few seconds apart (the login page, then the password POST), so the second is always refused.

After the fix, the same command (real run):

```
Sent:     80 requests (GET) over 7.9 s

== Timeline ==
  #1-#80   200  0.0-7.9 s

== Findings ==
  INFO  No limit reached  No 429 in 80 requests over 7.9 s at up to 10 per second. The limit is
                          higher than this probe goes, or it counts something other than this
                          client's requests.
  INFO  Quota headers     No X-RateLimit or RateLimit headers, so a client cannot see the limit
                          coming.
```

The probe never sends more than 10 requests a second, so it can't find a limit set at 10 r/s with a burst of 20, and isn't meant to. Its job is to explain a limit that real traffic is hitting, not to load-test one.

The probe's requests count against the same limit as everyone else's. In the lab it shares the gateway address with the browser, so a probe run can make a test login fail for the next few seconds. On a customer's system, use a test environment.

## Diagnosis

1. **Who sent the 429?** A page that says `nginx` at the bottom, `upstream=-` in the proxy's access log and nothing in Keycloak's log: the proxy refused it. A 429 from the application itself would have passed through the proxy with `upstream_status=429`.
2. **Which limit?** The error log names the zone (`by zone "kc_login"`). `nginx -T` shows its rate and the `limit_req` lines that use it, with their `burst`.
3. **What does a normal user need?** Count the requests a single login makes to the limited paths: here the authorisation request, then the password POST, plus a request for each extra step (a second factor, required actions, consent). They come within seconds of each other, so the limit must allow a short burst even if the long-term rate is low. That's what `burst=` is for; `nodelay` serves the burst at once instead of queueing it.
4. **Who counts as one client?** `limit_req_zone $binary_remote_addr` limits per client IP address *as nginx sees it*. Behind a NAT, a corporate proxy or another load balancer that's one address for many users. Here it's `client: 172.30.182.1` for every request, the Docker gateway. If the proxy is itself behind a load balancer, nginx needs the real client address (`set_real_ip_from` for the load balancer's addresses, and `real_ip_header X-Forwarded-For`) before a per-address limit means anything.
5. **No `Retry-After`.** nginx's `limit_req` sends no `Retry-After` and no quota headers. A client then has to guess when to retry:
   - A client that retries at once, or every second, keeps hitting the limit, and with a shared address it uses up everyone else's allowance too. Browsers don't retry a 429 at all: the user sees the error page and presses the button again.
   - A client that follows standard HTTP behaviour, and only waits as long as `Retry-After` says, has nothing to go on. Some fall back to a fixed retry, some give up.
   - Exponential back-off works (the probe got back in after 1, 2, 4, 8 s), but only by luck of timing, and only for clients that do it.

   If clients are expected to recover by themselves, have nginx send `Retry-After` on its 429s (see Fix).
6. **429 vs 503.** nginx's default for `limit_req` is **503**, not 429. This lab sets `limit_req_status 429`. Without it, the same refusal looks like this (captured from nginx 1.30.6 with the default):
   ```
   HTTP/1.1 503 Service Temporarily Unavailable
   ...
   2026/10/20 17:44:52 [error] 21#21: *2 limiting requests, excess: 1.000 by zone "z", client: 127.0.0.1, server: , request: "GET / HTTP/1.1", host: "localhost:8080"
   ```
   That's easy to misread as "the server is down". The error log line is the same; only the status differs. 503 also tells well-behaved clients the service is overloaded, not that *they* are sending too much.

**Root cause, in one sentence for the customer:** the reverse proxy's rate limit on Keycloak was lowered to 6 requests a minute with no burst, per client address, while a single login needs several requests within seconds and every user reaches the proxy from the same address, so logins are refused with 429 Too Many Requests before they reach Keycloak.

## Fix

1. Set a limit that real logins fit in, with a burst. In the lab:
   ```bash
   scripts/fix.sh proxy-rate-limit
   ```
   which restores `rate=10r/s` and `burst=20 nodelay`. By hand: edit `.state/proxy/rate-limit-zone.conf` and `.state/proxy/rate-limit.conf`, then
   ```bash
   docker compose exec proxy nginx -t
   docker compose exec proxy nginx -s reload
   ```
2. If the aim was to slow down password guessing, a per-address limit at the proxy is the wrong tool when many users share an address. Use Keycloak's brute-force detection (per user, in the realm's security defences) instead, or limit only the password POST (`/realms/<realm>/login-actions/authenticate`) with a burst that fits a few attempts.
3. To tell clients when to come back, send `Retry-After` with nginx's 429 (tested in nginx 1.30.6):
   ```nginx
   limit_req_status 429;
   location /realms/ {
       limit_req zone=kc_login burst=20 nodelay;
       error_page 429 @rate_limited;
       ...
   }
   location @rate_limited {
       add_header Retry-After 10 always;
       return 429 "Too many requests, retry in 10 seconds\n";
   }
   ```
   (`always` is needed: `add_header` otherwise only applies to successful responses.) Choose the value from the zone's rate: at 6 r/m the next request is allowed after 10 s.
4. Verify: a login through `:8185` completes, the proxy logs no new `limiting requests` lines, the probe reports `No limit reached` at its rate, and `scripts/status.sh` shows `healthy`.

## Prevention

- **Measure before you limit.** Count the requests a real login makes (with every authentication step in use), and set `burst` above that. Re-check when the login flow changes: a new second factor adds requests.
- **Know what one "client" is** at that proxy. Check `client:` in the error log or `$remote_addr` in the access log. If it's a gateway address, fix the real client address first.
- **Log and alert on `limiting requests`.** A sudden rise after a change is the change, not an attack. `limit_req_dry_run on` logs what a new limit *would* refuse without refusing it; try a new limit that way first.
- **Say when to retry:** `Retry-After` on 429s, and 429 rather than nginx's default 503.
- **Limits in config review,** with the reason for each one written next to it.

## Questions I'd ask the customer

1. What exactly does the error say, and what's at the bottom of the error page (`nginx`, a load balancer's name, or the app)? Is it 429 or 503?
2. Does it hit every user, or only users at one site or behind one VPN? Does the first login of the day work?
3. Was a rate limit added or changed on the proxy, load balancer or WAF recently? Why?
4. What client address does the proxy log for these requests? Is it the users' real addresses, or one address for everyone?
5. Do any of your clients (scripts, integrations, SDKs) retry on 429? How long do they wait, and do they look at `Retry-After`?
6. Can you send the proxy's error log lines (`limiting requests ... by zone`) and its configuration for that zone and location?
