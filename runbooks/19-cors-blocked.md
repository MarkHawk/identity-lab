# 19 · CORS: the API answers 200, the browser blocks the response

| | |
|---|---|
| **Protocol** | HTTP(S) from a script in a browser page to an API on **another origin** (scheme, host and port: `https://LAB_HOST:8182` calling `https://LAB_HOST:8188`), under the browser's CORS rules. A call carrying an `Authorization` header gets a **preflight** first (`OPTIONS` with `Access-Control-Request-Method`), then the real request. The browser only lets the page read the real response if that response's `Access-Control-Allow-Origin` matches the page's origin exactly. The token, its validation and the API are fine. |
| **Blast radius** | Every browser page on that origin that calls the API from script (single-page apps, the RP's "Call the API from the browser"), for every user. Server-side calls to the same API with the same token keep working, because CORS is a browser rule: the RP's own **Call the API** button, curl and other back-end clients are unaffected. |
| **Typical trigger** | A CORS allow-list edited by hand: an origin with a trailing slash or a path (copied from the address bar), `http` instead of `https`, a missing or extra port, a new front-end origin (a new domain, a staging URL, a port change) not added; CORS headers moved between the gateway and the app so that the preflight and the response no longer agree; a framework upgrade that changed how origins are matched. |
| **Lab** | `scripts/break.sh cors-blocked` · `scripts/fix.sh cors-blocked` (writes `https://LAB_HOST:8182/` to `.state/api/cors-allow-origin`, the Access-Control-Allow-Origin the API puts on its responses and re-reads on every request. The API's preflight answer, standing in for a gateway's, isn't touched.) |

## Symptom

Log in at https://LAB_HOST:8182/, and on the debug page click **Call the API from the browser**. The page says:

```
API call from the browser failed: TypeError: Failed to fetch
The browser gave this page no response. Its developer console (F12) says why.
```

That's all a script gets from a CORS refusal: no status, no headers, no body. It can't tell this apart from a network outage, so many front ends report it as *"network error"* or *"the server is unreachable"*.

The **browser's developer console** (F12 → Console) has the actual reason:

```
Access to fetch at 'https://idlab.home:8188/v1/whoami' from origin 'https://idlab.home:8182' has been blocked by CORS policy: The 'Access-Control-Allow-Origin' header has a value 'https://idlab.home:8182/' that is not equal to the supplied origin. Have the server send the header with a valid value.
Failed to load resource: net::ERR_FAILED
```

In the **Network** tab (F12 → Network), there are two requests to `/v1/whoami`: the preflight, `OPTIONS`, answered `204`, and the `GET`, whose status Chrome shows as *CORS error*. Its response body isn't available to look at.

Meanwhile **the API logs a success**. It answered the preflight, then validated the token and answered the real call with 200:

```
2026-10-22 18:44:43,561 INFO api event=api_cors_preflight origin=https://idlab.home:8182 method=GET headers=authorization
172.19.0.1 - - [22/Oct/2026:18:44:43 +0000] "OPTIONS /v1/whoami HTTP/1.1" 204 0 "https://idlab.home:8182/" "Mozilla/5.0 ... HeadlessChrome/153.0.8010.12 ..."
2026-10-22 18:44:43,568 INFO api event=api_request_ok sub=cfeca6fc-f25c-4695-8574-7c2d5b19863b azp=oidc-rp iat=2026-10-22T18:44:43Z exp=2026-10-22T18:49:43Z origin=https://idlab.home:8182 cors_allow_origin=https://idlab.home:8182/
172.19.0.1 - - [22/Oct/2026:18:44:43 +0000] "GET /v1/whoami HTTP/1.1" 200 156 "https://idlab.home:8182/" "Mozilla/5.0 ... HeadlessChrome/153.0.8010.12 ..."
```

**This is the point of this runbook: the server's evidence says success, the user's says failure, and both are true.** The API did its job. The browser then refused to hand the answer to the page, and only the browser knows that. Server-side monitoring, error rates and the API's own logs all show nothing wrong.

How customers describe it: *"The API is down from the web app, but it works in Postman,"* *"works with curl,"* or *"we get a network error, but your status page is green."* Postman and curl aren't browsers and don't apply CORS.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  cors-blocked                   broken   the API sends Access-Control-Allow-Origin: https://idlab.home:8182/ for origin https://idlab.home:8182

# The browser's comparison, done by hand: send the page's Origin, read the header back
curl -sS -D - -o /dev/null --cacert certs/ca.crt -H 'Origin: https://LAB_HOST:8182' \
  https://LAB_HOST:8188/healthz | grep -i '^access-control'
#  Access-Control-Allow-Origin: https://idlab.home:8182/       <- must be exactly https://idlab.home:8182

# The preflight, as the browser sends it
curl -sS -D - -o /dev/null --cacert certs/ca.crt -X OPTIONS -H 'Origin: https://LAB_HOST:8182' \
  -H 'Access-Control-Request-Method: GET' -H 'Access-Control-Request-Headers: authorization' \
  https://LAB_HOST:8188/v1/whoami | grep -iE '^HTTP|^access-control'
#  HTTP/1.1 204 NO CONTENT
#  Access-Control-Allow-Origin: https://idlab.home:8182
#  Access-Control-Allow-Methods: GET
#  Access-Control-Allow-Headers: Authorization

# The API's view: the browser's calls, and what it answered them with
docker compose logs --since 10m api | grep -E 'api_cors_preflight|api_request_ok.*origin=https'

# The setting itself
cat .state/api/cors-allow-origin
```

The two curl answers disagree: the preflight allows the origin, the real response names a slightly different one. That's why the browser sent the call (the API logged it) and then blocked the answer.

To capture the browser's side from a user, ask for the **Console** messages and a **HAR file** (Network tab → *Export HAR*). A HAR includes request headers and cookies, so it can hold tokens and session cookies: ask for it to be sanitised, or capture it in a test account, and treat it as a secret.

## Diagnosis

1. **Is it CORS at all?** Signs: the failure only happens from a browser page on another origin; the same call from curl, Postman or a back end works; the page's script sees a generic `TypeError: Failed to fetch` (or `Network Error` in axios, status `0` in XMLHttpRequest); the console says *blocked by CORS policy*. If the API's own log has no line for the call, it may be a preflight failure (point 4) or a real network problem.
2. **Read the console's reason. The wording says what to fix.** Chromium's messages for the real response:

   | Console says | Meaning |
   |---|---|
   | `The 'Access-Control-Allow-Origin' header has a value 'https://idlab.home:8182/' that is not equal to the supplied origin.` | The header is there but not an exact match. **This scenario** (a trailing slash). The same message for `http` vs `https`, a missing port, or another origin. |
   | `No 'Access-Control-Allow-Origin' header is present on the requested resource.` | No header at all: the origin isn't on the allow-list, or the layer that adds CORS headers isn't in this response's path. Captured in this lab by emptying the setting. |
   | `The value of the 'Access-Control-Allow-Origin' header ... must not be the wildcard '*' when the request's credentials mode is 'include'.` | The page sends cookies (`credentials: "include"`) and the API answers `*`. It must name the origin and send `Access-Control-Allow-Credentials: true`. |
   | `The 'Access-Control-Allow-Origin' header contains multiple values ..., but only one is allowed.` | Two layers (say a gateway and the app) both add the header. |

3. **An origin is exact.** It is scheme, host and port, nothing else: no path, no trailing slash, no wildcard sub-domains in the header itself. `https://idlab.home:8182`, `https://idlab.home:8182/`, `http://idlab.home:8182` and `https://idlab.home` are four different values, and only the first matches this page. The header must repeat the page's origin character for character (or be `*`, for calls without credentials).
4. **The other common case: the preflight itself fails.** A cross-origin call with an `Authorization` header (or JSON content type, or a method other than GET, HEAD and POST) isn't a "simple" request. The browser first sends `OPTIONS` and only sends the real request if the preflight answer allows the origin, the method and the headers. **If the preflight fails, the GET never arrives.** The API's log then has only the `OPTIONS` line, often with a 200 or 204, which looks fine, and no `GET` and no `api_request_ok` at all. The console says so: *Response to preflight request doesn't pass access control check: ...*, followed by the reason (no `Access-Control-Allow-Origin`, a mismatch, or `Request header field authorization is not allowed by Access-Control-Allow-Headers in preflight response`). Other ways to get there: the preflight is redirected (to a login page, or http → https), it hits authentication and gets a 401 (preflights never carry the token), or a firewall or WAF drops `OPTIONS`. The lab doesn't break the preflight: its API answers preflights permissively, as a gateway in front of the app often does, which is why its calls reach the app here. So the server-side question to ask is **"which requests from that origin arrived, OPTIONS only or OPTIONS and GET?"** That tells you whether the browser stopped before or after sending the call.
5. **Why the preflight passed here and the response didn't.** Preflights and real responses are often answered by different layers: an API gateway, ingress or load balancer that answers `OPTIONS` itself, and the application (or its framework middleware) that sets headers on real responses. Each has its own CORS settings, and they drift. The browser checks both, and the call fails if either one is wrong.
6. **Why it isn't the token.** The API logged `api_request_ok` with the user's `sub`: the token was valid. CORS never makes a server reject anything. It decides what a browser lets a page read. A 401 or 403 from the API would be readable by the page if the CORS headers were right, and is then a different problem (runbook 16).
7. **CORS isn't security for the API.** It protects users' browsers from pages on other origins reading responses with their credentials. Any non-browser client ignores it, so the API must still check every token, as this one does.

**Root cause, in one sentence for the customer:** the API's CORS setting names the web app's origin with a trailing slash, so although the API accepts the call and answers it successfully, browsers see an `Access-Control-Allow-Origin` that doesn't exactly match the page's origin and refuse to give the answer to the page.

## Fix

1. Make the API's `Access-Control-Allow-Origin` match the page's origin exactly. In the lab:
   ```bash
   scripts/fix.sh cors-blocked
   ```
   By hand, write `https://LAB_HOST:8182` (no trailing slash) to `.state/api/cors-allow-origin`. The API re-reads it on the next request. In real deployments, fix it in the layer that sets the header on real responses (application config, framework middleware or gateway response mapping), and check that the preflight's settings agree.
2. Verify: the curl with `Origin:` above returns the exact origin, **Call the API from the browser** shows `API call from the browser succeeded: 200`, the console is clean, and `scripts/status.sh` shows `healthy`.
3. Users don't need to clear anything. The browser doesn't cache the blocked response, and a cached preflight (`Access-Control-Max-Age`) only remembers what the preflight allowed, which was right all along.

Don't fix it by answering `Access-Control-Allow-Origin: *` everywhere, or by echoing back whatever `Origin` arrives. The first breaks calls with credentials and invites any site to read the responses. The second does the same and hides it. Use an explicit allow-list of origins, and echo the request's origin only when it is on that list (with `Vary: Origin`).

## Prevention

- **Store origins, not URLs, in CORS allow-lists,** and validate them when the setting is changed: scheme, host and optional port, no path, no trailing slash.
- **Configure CORS in one place,** or test that the gateway's preflight answer and the application's response headers agree. A synthetic browser test from each front-end origin (as `scripts/test.sh` does with a headless browser) catches both halves.
- **Log the `Origin` header and the `Access-Control-Allow-Origin` sent,** as this API does in `api_request_ok`, so a "success" line from a browser can be checked against the page's origin without the user's console.
- **Report front-end errors.** A `TypeError: Failed to fetch` reported from the page, with the target URL, is often the only signal a team gets. Most error-reporting tools can capture console errors as well.

## Questions I'd ask the customer

1. What does the browser's developer console say, word for word? Can you send a screenshot of the Console and the Network tab for the failing call?
2. What is the exact origin of the page making the call (the address bar up to the first `/` after the host and port)?
3. Does the same request work from curl or Postman? Does it work from another page or origin?
4. In the Network tab, is there an `OPTIONS` request before the call? What status does it get, and does the call itself appear after it?
5. What changed recently: the web app's domain or port, the API's CORS configuration, a gateway, a framework upgrade?
6. Does the page send cookies or credentials with the call (`credentials: "include"`, `withCredentials`)?
