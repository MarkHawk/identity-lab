# 17 · Reverse proxy: 503 Service Unavailable (maintenance mode left on)

| | |
|---|---|
| **Protocol** | HTTP(S) between the browser and the nginx reverse proxy in front of Keycloak (`https://LAB_HOST:8183`). Nothing identity-specific has failed: Keycloak, its database and the directory are healthy. The proxy refuses the requests itself. |
| **Blast radius** | Every sign-in that goes through that proxy route: the SAML SP and the OIDC RP behind the proxy (`:8184`, `:8185`), for every user. Keycloak reached directly (`:8180`) and the apps that use it (`:8181`, `:8182`) keep working. So does the proxy's own health check, so monitoring stays green. |
| **Typical trigger** | Maintenance mode switched on for an upgrade window (of Keycloak, its database or the proxy) and not switched off afterwards; a maintenance flag or page left in a config that was copied or rolled back; a deployment that turned it on and failed before its last step. |
| **Lab** | `scripts/break.sh proxy-maintenance` · `scripts/fix.sh proxy-maintenance` (puts a `return 503` with a maintenance page and `Retry-After` in `.state/proxy/kc-maintenance.conf`, included in the Keycloak locations of the proxy's `:8183` server, and reloads nginx; Keycloak isn't touched) |

## Symptom

Go to https://LAB_HOST:8184/ and click **Log in with SAML**. Where Keycloak's login form should be, the browser shows the maintenance page:

```
Sign-in is down for planned maintenance
We are upgrading the sign-in service. Please try again later.
```

The response is a 503 from nginx, with a `Retry-After` header:

```
HTTP/1.1 503 Service Temporarily Unavailable
Server: nginx
Content-Type: text/html
Content-Length: 205
Retry-After: 3600
```

The OIDC RP behind the proxy (`:8185`) breaks too, in one of two ways depending on what it has cached:

- **If the RP has already cached Keycloak's discovery document** (it has served a login since it started), the browser is sent to Keycloak through the proxy and gets the same maintenance page.
- **If it hasn't** (it has just started), it fails one step earlier. The RP fetches the discovery document through the proxy on its back channel, gets the 503 itself, and shows its own error page:
  ```
  OIDC login failed
  503 Server Error: Service Temporarily Unavailable for url: https://proxy:8183/realms/idlab/.well-known/openid-configuration
  Error code backchannel_failed
  ```
  The RP logs:
  ```
  2026-10-22 18:33:40,759 WARNING oidc-rp event=oidc_login_failed reason=backchannel_failed error='503 Server Error: Service Temporarily Unavailable for url: https://proxy:8183/realms/idlab/.well-known/openid-configuration' detail='HTTPError fetching https://proxy:8183/realms/idlab/.well-known/openid-configuration'
  ```

Either way, the evidence is the proxy's access log. Every request to Keycloak gets a 503, and **no upstream is named**:

```
172.30.182.1 "GET /realms/idlab/protocol/saml?SAMLRequest=***&RelayState=%2Fdebug&Signature=***&SigAlg=... HTTP/1.1" 503 205 host=idlab.home:8183 upstream=- upstream_status=- request_time=0.000 upstream_time=-
```

The error log has nothing: nginx did what it was configured to do. Keycloak's log has nothing either, because the requests never reached it.

How customers describe it: *"SSO is down, it says maintenance, but the maintenance window ended hours ago,"* while the identity team says *"Keycloak is up, all health checks are green."* Both are right.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  proxy-maintenance              broken   kc-maintenance.conf: return 503 with a maintenance page (maintenance mode is on)

# The status line and headers, through the proxy
curl -sS -D - -o /dev/null --cacert certs/ca.crt https://LAB_HOST:8183/realms/idlab/.well-known/openid-configuration
#  HTTP/1.1 503 Service Temporarily Unavailable
#  Retry-After: 3600

# The same document straight from Keycloak: it is fine
curl -sS -o /dev/null -w '%{http_code}\n' --cacert certs/ca.crt https://LAB_HOST:8180/realms/idlab/.well-known/openid-configuration
#  200

# The proxy's access log: 503 with upstream=- means nginx answered by itself
docker compose logs --since 10m proxy | grep -E '" 503 .*host=[^ ]*:8183'

# Where the 503 comes from, include files expanded
docker compose exec proxy nginx -T 2>/dev/null | grep -A6 '^# configuration file /etc/nginx/idlab/kc-maintenance.conf'
#  # configuration file /etc/nginx/idlab/kc-maintenance.conf:
#  ...
#  default_type text/html;
#  add_header Retry-After 3600 always;
#  return 503 '<!doctype html>...
```

## Diagnosis

1. **Who wrote the 503?** The body is the first clue: a branded maintenance page, nginx's plain `503 Service Temporarily Unavailable` page, or Keycloak's own styling. The access log settles it. `upstream=-` means **nginx didn't contact any upstream**: a configured `return`, a rate or connection limit, or a maintenance switch. A 503 that Keycloak sent would show Keycloak's address and `upstream_status=503`.
2. **How 503 differs from 502 and 504** (runbooks 06 and 07). All three come from the proxy, and the access log's upstream fields tell them apart:

   | Status | What happened | Access log | Error log |
   |---|---|---|---|
   | **503** (this scenario) | The proxy chose not to forward the request. | `upstream=- upstream_status=-` | nothing, or `limiting requests` / `limiting connections` |
   | **502** (runbook 06) | The proxy tried, and the upstream couldn't be reached or sent an invalid answer. | an upstream address, `upstream_status=502` | `connect() failed`, `prematurely closed`, `SSL_do_handshake() failed`, `no live upstreams`, ... |
   | **504** (runbook 07) | The proxy reached the upstream, which didn't answer in time. | an upstream address, `upstream_status=504`, `upstream_time` at the timeout | `upstream timed out` |

   So **503 is about the proxy's own decision. 502 and 504 are about the upstream.**
3. **Other things that answer 503 in an identity stack.** nginx only sends a 503 when it's configured to. Know where else one can come from:

   | Where | When |
   |---|---|
   | nginx `return 503` / maintenance page | **This scenario.** |
   | nginx `limit_req` / `limit_conn` | Rate or connection limits answer 503 unless `limit_req_status` / `limit_conn_status` say otherwise. This lab sets 429 for its rate limit (runbook 08). The error log says `limiting requests` or `limiting connections`. |
   | HAProxy, and cloud load balancers | No server available to send the request to. HAProxy: *No server is available to handle this request* when every backend is down. AWS ALB: 503 when the target group has **no registered targets**. These are the cases where "no healthy upstream" really is a 503. nginx open source answers 502 for them (`no live upstreams`). |
   | Keycloak itself | Its readiness endpoint, `/health/ready`, answers 503 while Keycloak isn't ready (database unreachable, still starting). With `http-max-queued-requests` set, requests beyond the queue get 503. A Keycloak that is still starting usually refuses connections, which the proxy reports as a 502. |
   | Squid (egress) | `503 Service Unavailable` when Squid can't resolve or connect to the destination (`ERR_DNS_FAIL`, `ERR_CONNECT_FAIL`). The app behind it shows that 503 as a back-channel error. |

4. **Retry-After is a hint about intent.** A deliberate 503 (maintenance or overload) should carry `Retry-After`; an accidental one usually doesn't. Here it says "come back in an hour", which is exactly what the page told users when the window started, and it is still saying so.
5. **Why monitoring missed it.** The proxy's health check (`/nginx-healthz`) and Keycloak's (`/health/ready` on the management port) both still pass: neither goes through the maintenance switch. Only a check that signs in, or fetches a Keycloak URL through the proxy, sees the 503.
6. **Why the OIDC RP's error varies.** It fetches Keycloak's discovery document on its back channel through the same proxy, and caches it. A freshly started RP fails at that step, with the 503 in its own log. One that already has it cached sends the browser to Keycloak, and the browser gets the maintenance page. Different screenshots from different users can have one cause.

**Root cause, in one sentence for the customer:** the reverse proxy in front of Keycloak was left in maintenance mode after the upgrade, so it answers every sign-in request with its maintenance page (HTTP 503) without passing it on to Keycloak, which is up and healthy.

## Fix

1. Turn maintenance mode off on the proxy. In the lab:
   ```bash
   scripts/fix.sh proxy-maintenance
   ```
   By hand, empty `.state/proxy/kc-maintenance.conf` (comments only), then:
   ```bash
   docker compose exec proxy nginx -t          # test before reloading
   docker compose exec proxy nginx -s reload
   ```
2. Verify: the discovery document through the proxy answers 200, the proxy's access log shows `upstream=` with Keycloak's address and `upstream_status=200`, a login at https://LAB_HOST:8184/ works, and `scripts/status.sh` shows `healthy`.
3. Users who saw the page can retry straight away. Browsers don't cache a 503, and nothing waits for `Retry-After`.

Before turning it off in a real environment, confirm the maintenance really is finished: ask whoever turned it on. A switch left on by mistake looks the same as one still needed because the upgrade isn't done.

## Prevention

- **Make maintenance mode expire.** Put an end time in it (or a ticket number and owner in the page or a header), and make the end of every change ticket "maintenance mode off, sign-in tested through the proxy".
- **Monitor through the proxy with a real sign-in** (or at least a Keycloak URL on the public route), not only the proxy's and Keycloak's own health checks.
- **Alert on 503 with `upstream=-`** in the proxy's access log, separately from upstream errors. Keep `$upstream_addr` and `$upstream_status` in the log format so the two can be told apart.
- **Let the maintenance page say when it started and who to ask.** That turns a "SSO is down" ticket into a one-line question.

## Questions I'd ask the customer

1. What exactly does the page say, and does it carry your branding, nginx's, or Keycloak's?
2. Was there a maintenance window or a change on the proxy, load balancer or Keycloak recently? Who ran it, and was maintenance mode switched off at the end?
3. Does Keycloak answer when reached without the proxy? Are its health checks green?
4. Does the response have a `Retry-After` header? Does the proxy's access log name an upstream for the failing requests?
5. Is it every user and every app that signs in through this proxy, or only some?
6. If you have several proxies or load balancer nodes: is it all of them, or only one (one node left in maintenance)?
