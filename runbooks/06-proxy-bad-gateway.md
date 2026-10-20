# 06 · Reverse proxy: 502 Bad Gateway

| | |
|---|---|
| **Protocol** | HTTP(S) between the browser and an nginx reverse proxy, and between nginx and the app behind it (the "upstream"). Nothing identity-specific has failed: Keycloak, the directory and the app itself are healthy. |
| **Blast radius** | Everything behind that one proxy route (here `https://LAB_HOST:8185`, the OIDC RP behind the proxy). The same app reached another way (the direct `:8182`) keeps working, which is the quickest way to tell a proxy fault from an app fault. |
| **Typical trigger** | A proxy config change: `http://` written where the backend only speaks HTTPS (or the other way round), a wrong upstream port after an app moved, a copied config block, or the backend container replaced and no longer at the address the proxy uses. |
| **Lab** | `scripts/break.sh proxy-bad-gateway` · `scripts/fix.sh proxy-bad-gateway` (changes `proxy_pass` in `.state/proxy/oidc-rp-upstream.conf` from `https://` to `http://` and reloads nginx; the app is not touched) |

## Symptom

Go to https://LAB_HOST:8185/. Before the app's own page appears, nginx answers with its plain error page:

```
HTTP/1.1 502 Bad Gateway
Server: nginx
Content-Type: text/html
Content-Length: 150

<html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

502 means **the proxy is up, but it couldn't get a valid response from the server behind it**. The browser never reached the app, so there is no app error page, no login and no Keycloak involvement. Every page on that route fails the same way, immediately (here in a few milliseconds, not after a timeout).

The proxy logs the reason in its error log, one line per request:

```
2026/10/20 17:34:02 [error] 1278#1278: *256 upstream prematurely closed connection while reading response header from upstream, client: 172.30.182.1, server: , request: "GET / HTTP/1.1", upstream: "http://172.30.182.3:8182/", host: "idlab.home:8185"
```

and its access log shows the same request, with the upstream it tried:

```
172.30.182.1 "GET / HTTP/1.1" 502 150 host=idlab.home:8185 upstream=172.30.182.3:8182 upstream_status=502 request_time=0.004 upstream_time=0.004
```

The app saw the request too, and says why it hung up:

```
[2026-10-20 17:34:02 +0000] [7] [WARNING] Invalid request from ip=172.30.182.10: [SSL: HTTP_REQUEST] http request (_ssl.c:1032)
```

How customers describe it: *"The app is down, we get Bad Gateway,"* while the app team says *"Our health checks are green."* Both are right.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  proxy-bad-gateway              broken   oidc-rp-upstream.conf: proxy_pass http://oidc_rp_proxied; (the upstream speaks HTTPS only)

# The proxy's error log: the decisive line
docker compose logs proxy | grep -E '\[(error|crit)\]'
#  ... upstream prematurely closed connection while reading response header from upstream, ...
#      upstream: "http://172.30.182.3:8182/", host: "idlab.home:8185"

# The upstream's own log
docker compose logs oidc-rp-proxied | grep -i invalid
#  ... [WARNING] Invalid request from ip=172.30.182.10: [SSL: HTTP_REQUEST] http request (_ssl.c:1032)

# What nginx is actually configured with, and which file each line is in
docker compose exec proxy nginx -T 2>/dev/null | grep -E '^# configuration file|proxy_pass'
#  # configuration file /etc/nginx/idlab/oidc-rp-upstream.conf:
#  proxy_pass http://oidc_rp_proxied;
```

The `upstream:` field is the most useful part of the error line: it shows the **scheme, address and port nginx really used**. Here it's `http://`, to a port where the app expects TLS.

Then take the proxy out of the picture and call the upstream from the proxy's own container, the same network path nginx uses:

```bash
# As the app expects it: HTTPS. (--connect-to: the app's certificate is issued
# for the name oidc-rp, the container is called oidc-rp-proxied.)
docker compose exec proxy curl -sS -o /dev/null -w '%{http_code}\n' --cacert /etc/idlab/ca.crt \
  --connect-to oidc-rp:8182:oidc-rp-proxied:8182 https://oidc-rp:8182/healthz
#  200

# As the proxy is sending it: plain HTTP.
docker compose exec proxy curl -sS -o /dev/null -w '%{http_code}\n' http://oidc-rp-proxied:8182/healthz
#  000
#  curl: (52) Empty reply from server
```

The app answers HTTPS and drops plain HTTP. The app is fine; the proxy is talking to it the wrong way.

## Diagnosis

1. **502 vs 504 vs 5xx from the app.** A 502 page that says `nginx` at the bottom was written by the proxy, not the app. A 504 (runbook 07) means the upstream accepted the request but was too slow. A 500 or 503 with the app's own styling came from the app.
2. **Is it the proxy or the app?** Reach the app another way: directly (here `https://LAB_HOST:8182`), from the proxy container with curl as above, or with the app's own health check. If that works, the fault is in the proxy's route to the app.
3. **Read the error log line, not just the status.** The same 502 has different causes, and nginx names each one. All of these were captured in this lab:

   | Proxy error log | Meaning |
   |---|---|
   | `upstream prematurely closed connection while reading response header from upstream` with `upstream: "http://..."` | nginx connected and sent plain HTTP; the upstream hung up without answering. Usually HTTP to an HTTPS-only port. **This scenario.** The app logs `[SSL: HTTP_REQUEST] http request`. |
   | `connect() failed (111: Connection refused) while connecting to upstream` | The host is there but nothing listens on that port: a wrong port, or the app not started yet. |
   | `connect() failed (113: Host is unreachable) while connecting to upstream` | Nothing at that address at all. In the lab: the upstream container was stopped. |
   | `SSL_do_handshake() failed (SSL: error:0A00010B:SSL routines::wrong version number) while SSL handshaking to upstream` | The reverse: `https://` to a port that speaks plain HTTP. (Captured by pointing the route at Keycloak's plain-HTTP management port.) |
   | `upstream sent too big header while reading response header from upstream` | The upstream answered, but its headers didn't fit the proxy's buffer (runbook 10). |

4. **Check the change history of the proxy, not just the app.** Proxy config often lives in a different repository, team or appliance. Ask what changed on the proxy around the time the 502s started. `nginx -T` shows the configuration nginx would load right now, including every included file.
5. **HTTPS to the upstream?** If TLS from the proxy to the app is required (as here, `proxy_ssl_verify on`), `proxy_pass` must say `https://`. The reverse mistake, HTTPS to a plain HTTP port, is also a 502, logged as the `wrong version number` handshake failure in the table.

**Root cause, in one sentence for the customer:** the reverse proxy was changed to send plain HTTP to the app, which only accepts HTTPS, so the app closes every connection and the proxy returns 502 Bad Gateway for every request on that route; the app itself is healthy.

## Fix

1. Correct the upstream in the proxy's configuration. In the lab:
   ```bash
   scripts/fix.sh proxy-bad-gateway
   ```
   By hand, that's `proxy_pass https://oidc_rp_proxied;` in `.state/proxy/oidc-rp-upstream.conf`, then:
   ```bash
   docker compose exec proxy nginx -t          # test before reloading
   docker compose exec proxy nginx -s reload   # no restart, no dropped connections
   ```
2. Verify: https://LAB_HOST:8185/ shows the app, the proxy's access log shows `200` with `upstream_status=200`, and `scripts/status.sh` shows `healthy`.

Don't "fix" it by turning off TLS on the app, or by turning off `proxy_ssl_verify`. Both hide the mistake and leave traffic between the proxy and the app unprotected.

## Prevention

- **Test the config before it goes live,** and test the route, not just the syntax. `nginx -t` passed here: the config was valid, just wrong. A synthetic request through the proxy after every change catches it.
- **Monitor through the proxy,** not only the app. The app's own health check stayed green the whole time.
- **Alert on the proxy's 502 rate,** and keep `$upstream_addr` and `$upstream_status` in the access log so a 502 says which upstream failed.
- Keep proxy configuration in version control with review, next to the app it fronts, so a backend's port or scheme change and the proxy change go in together.

## Questions I'd ask the customer

1. Does the 502 page show `nginx` (or your load balancer's name) at the bottom, or the app's own styling?
2. Does the app work when reached directly, bypassing the proxy? Are the app's own health checks green?
3. What changed on the proxy or load balancer recently: config, certificates, a new backend address or port?
4. Does the backend expect HTTPS or plain HTTP? Which does the proxy send?
5. Can you send the proxy's error log lines for a failing request (the `upstream:` field in particular)?
6. Is every page on that site failing, or only some paths?
