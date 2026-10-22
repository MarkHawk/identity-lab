# 15 · Redirect loop: "too many redirects" behind the reverse proxy

| | |
|---|---|
| **Protocol** | HTTP(S) through an nginx reverse proxy that ends TLS and talks plain HTTP to the app behind it, as most load balancers do. The app forces HTTPS: any request that looks like plain HTTP is redirected to its `https://` URL. Behind a proxy, the app only knows the browser used HTTPS because the proxy says so in `X-Forwarded-Proto`, and only believes it from the proxies it trusts. |
| **Blast radius** | Every page of the one app behind that proxy route, for every user, before any login. Other routes through the same proxy, and Keycloak, are fine. |
| **Typical trigger** | A `proxy_set_header` added to a `location` (for tracing, WebSockets or CORS), which makes nginx drop every `proxy_set_header` the location used to inherit; TLS moved from the app to a proxy or load balancer, with the app still forcing HTTPS; a new proxy hop, so the app trusts the wrong number of proxies; a proxy that passes on a load balancer's `X-Forwarded-Proto` when there's no load balancer in front of it. |
| **Lab** | `scripts/break.sh redirect-loop` · `scripts/fix.sh redirect-loop` (adds `proxy_set_header X-Request-ID $request_id;` to `.state/proxy/edge-location.conf`, included in the location of the proxy's `:8187` server, and reloads nginx; the app isn't touched) |

## Symptom

Go to https://LAB_HOST:8187/. The page never loads. Chrome shows its own error page:

```
This page isn't working
idlab.home redirected you too many times.
Try deleting your cookies.
ERR_TOO_MANY_REDIRECTS
```

Firefox says *The page isn't redirecting properly*, and Safari *Too many redirects occurred trying to open "https://idlab.home:8187/"*. Nothing from the app or Keycloak is ever shown, so there's no login to try.

The app logs one line for every redirect, about 20 for each attempt (that's how many Chrome follows before giving up):

```
2026-10-22 08:44:57,240 INFO oidc-rp event=force_https path=/ scheme=http x_forwarded_proto=-
```

and the proxy logs a 302 from the app for each of them:

```
172.30.182.1 "GET / HTTP/1.1" 302 235 host=idlab.home:8187 upstream=172.30.182.5:8182 upstream_status=302 request_time=0.001 upstream_time=0.001
```

How customers describe it: *"the app says too many redirects"*, *"clearing cookies didn't help"*, or *"it works on the server itself but not through the load balancer"*. Browsers suggest deleting cookies because a cookie is the usual cause of a loop between two pages. Here there's only one page, redirecting to itself, and no cookie is involved.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  redirect-loop                  broken   GET https://idlab.home:8187/ redirects to itself (edge-location.conf: proxy_set_header X-Request-ID $request_id)

# One request, without following redirects: where does it send the browser?
curl -sS -I --cacert certs/ca.crt https://LAB_HOST:8187/
#  HTTP/1.1 302 FOUND
#  Server: nginx
#  Location: https://idlab.home:8187/      <- the URL that was just asked for

# Follow them, as a browser would
curl -sS -L --max-redirs 5 --cacert certs/ca.crt -o /dev/null -w '%{num_redirects} %{url_effective}\n' https://LAB_HOST:8187/
#  curl: (47) Maximum (5) redirects followed
#  5 https://idlab.home:8187/

# What the app thinks of each request
docker compose logs --since 5m oidc-rp-edge | grep force_https

# The headers the proxy really sends in that location, include files expanded
docker compose exec proxy nginx -T 2>/dev/null | sed -n '/listen 8187/,/^    }/p'
docker compose exec proxy nginx -T 2>/dev/null | grep -A4 '^# configuration file /etc/nginx/idlab/edge-location.conf'
#  # configuration file /etc/nginx/idlab/edge-location.conf:
#  ...
#  proxy_set_header X-Request-ID $request_id;
```

In the browser's developer tools (Network tab, **Preserve log** on), the same request appears again and again with status `302` and the same `Location`.

One more clue is in the app's access log: the client address is the proxy's (`172.30.182.10`), where it was the browser's (`172.30.182.1`) before the change. `X-Forwarded-For` went missing at the same time as `X-Forwarded-Proto`.

## Diagnosis

1. **A redirect to the same URL is a loop about the scheme or the host, not about the page.** The app is saying "come back over HTTPS" to a browser that already is. So the question is why the app thinks the request was plain HTTP. The `force_https` log line answers it: `scheme=http` with `x_forwarded_proto=-` means the header never arrived.
2. **Why the header disappeared: nginx's `proxy_set_header` inheritance.** A `location` inherits the `proxy_set_header` lines of its `server` (or `http`) block **only if it has none of its own**. One `proxy_set_header` in the location replaces the whole inherited set. It doesn't add to it. The config still shows `X-Forwarded-Proto $scheme` at server level, so it looks correct to anyone reading it. Only `nginx -T` with the location's include files, read together, shows it. (`add_header`, `proxy_hide_header` and several other array-like directives behave the same way.) Note that `Host` falls back to nginx's default, the upstream's name, at the same time. This app redirects to its configured public URL, so that changes nothing here. An app that builds its redirect from `Host` instead would send the browser to `https://oidc_rp_edge/`, which it can't reach: a different error with the same cause.
3. **Other ways to get the same loop.** All of these were tried in the lab, with what the browser got:

   | Proxy sends / app trusts | Result |
   |---|---|
   | `X-Forwarded-Proto $scheme` at server level, nothing in the location; app trusts 1 proxy (healthy) | 200 |
   | `X-Request-ID` added in the location (**this scenario**) | loop |
   | `X-Request-ID` added in the location, with `Host`, `X-Forwarded-For` and `X-Forwarded-Proto` repeated there too | 200 |
   | `X-Request-ID` and `Host` in the location, `X-Forwarded-Proto` not repeated | loop |
   | `X-Forwarded-Proto http` (hard-coded, or a load balancer's value passed on when it talks HTTP to nginx) | loop |
   | `X-Forwarded-Proto $http_x_forwarded_proto` (copied from a setup behind a load balancer), no load balancer in front | loop |
   | the same, but the client sends `X-Forwarded-Proto: https` itself | 200: the client chooses the scheme the app trusts. Don't do this. |
   | healthy proxy, app trusts **0** proxies (`OIDC_RP_PROXY_HOPS=0`: header ignored) | loop |
   | healthy proxy, app trusts **2** proxies but there's only one | loop, logged as `scheme=http x_forwarded_proto=https` |

   The last row is easy to miss: the header arrives with the right value, but the app was told to expect a list of two (Werkzeug's `ProxyFix` takes the value the second proxy from the right appended), finds only one, and ignores it. Every framework has an equivalent setting (Django's `SECURE_PROXY_SSL_HEADER`, Spring's `server.forward-headers-strategy`, Express's `trust proxy`), and where it takes a number of hops, that number must match the real number of proxies.
4. **Trusting too much is the opposite risk.** Here a forged header from a browser does nothing, because nginx *replaces* `X-Forwarded-Proto` with its own value (a request with `X-Forwarded-Proto: http` to the healthy proxy still gets a 200). If the proxy passed on the client's header, or the app trusted it from anyone (`ProxyFix` with more hops than there are proxies, or an app port reachable without the proxy), any client could pick the scheme, and with `X-Forwarded-For` the address, that the app logs and acts on.
5. **Why it isn't cookies, the browser or the app's code.** Clearing cookies or using a private window doesn't help. The same app answers 200 for anyone who sends the header (`curl -H 'X-Forwarded-Proto: https'` from inside the proxy network), and nothing in the app changed.

**Root cause, in one sentence for the customer:** a header line added to the proxy's configuration for this app made the proxy stop telling the app that browsers connect over HTTPS, so the app, which only accepts HTTPS, redirects every request to the HTTPS address the browser is already on, and browsers give up after about 20 redirects.

## Fix

1. Make the location send the forwarded headers again. In the lab:
   ```bash
   scripts/fix.sh redirect-loop
   ```
   By hand, either take the extra line out, or keep it and repeat every header the location needs, since it no longer inherits any:
   ```nginx
   location / {
       proxy_set_header X-Request-ID      $request_id;
       proxy_set_header Host              $http_host;
       proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;
       proxy_pass http://oidc_rp_edge;
   }
   ```
   then `nginx -t` and `nginx -s reload`. If another load balancer ends TLS in front of nginx, send *its* scheme, not nginx's own `$scheme`, and say so in the config.
2. Verify: `curl -sS -I https://LAB_HOST:8187/` answers `200`, the app logs no more `force_https` lines for it, a login at https://LAB_HOST:8187/ works, and `scripts/status.sh` shows `healthy`.
3. If users still loop after the fix, their browsers may have cached a **301** from an app that redirects permanently (this one uses 302 for that reason). A private window, or clearing the site's cached data, proves it. Cookies have nothing to do with it.

Don't fix it by switching off the app's HTTPS redirect, or by making it trust `X-Forwarded-Proto` from everyone: either one removes a protection to hide a proxy mistake.

## Prevention

- **Keep all of a route's `proxy_set_header` lines at one level,** or in one shared include file used by every location, so adding one can't silently remove the others.
- **Check the headers the app receives after every proxy change,** for example with a debug endpoint that echoes `X-Forwarded-*` (lab-only), or the app's own log, not just the proxy's config.
- **Set the app's trusted proxy count to the real number of hops,** and change it when you add or remove a load balancer.
- **Alert on a burst of 3xx responses to the same URL** from one client in the proxy's access log. That's how a loop shows up there.

## Questions I'd ask the customer

1. Does it fail on every page and for every user, before any login? Does a private window or another browser behave the same?
2. What does `curl -sS -I` on the failing URL return: which status, and which `Location`? Is it the same URL?
3. Where does TLS end: at the app, at a proxy or at a load balancer? How many proxies are in front of the app, and what changed in any of them recently?
4. Which `X-Forwarded-*` (or `Forwarded`) headers does the app receive, and with which values, as the app itself sees them?
5. How is the app told which proxies to trust, and how many hops does that setting expect?
6. Does the app redirect with 301 or 302? If 301, have users who saw the loop cleared the site's cached data since the fix?
