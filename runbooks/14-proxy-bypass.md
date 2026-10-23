# 14 · Egress proxy: NO_PROXY sends IdP traffic around the proxy

| | |
|---|---|
| **Protocol** | The client-side proxy settings `HTTPS_PROXY` and `NO_PROXY`, which decide per request whether an app server's HTTPS call goes through the egress proxy or straight to the destination. Here, the OIDC RP's back channel to Keycloak: discovery, token, userinfo and JWKS. |
| **Blast radius** | The one app (or host, or image) whose settings changed, for every destination that now matches `NO_PROXY`. Here, every login on the OIDC RP at `https://LAB_HOST:8186`. The proxy, Keycloak and the other apps are untouched. |
| **Typical trigger** | A `NO_PROXY` list copied from another environment or a base image ("internal names never go through the proxy"); the IdP moving from an external to an internal name, or the other way round; a deployment template that sets `NO_PROXY` for all apps; or a typo that makes the list match more, or less, than intended. |
| **Lab** | `scripts/break.sh proxy-bypass` · `scripts/fix.sh proxy-bypass` (adds `keycloak,.idlab.example` to `NO_PROXY` in `.state/oidc-rp-egress/proxy.env` and recreates the `oidc-rp-egress` container, as a redeploy would; Squid isn't touched). Both save the old container's logs first, to `.state/oidc-rp-egress/logs/<UTC time>/logs/oidc-rp-egress.log`, newest 5 kept |

## Symptom

Go to https://LAB_HOST:8186/ and click **Log in with OIDC**. Straight away, before any Keycloak page, the app shows **OIDC login failed**:

```
HTTPSConnectionPool(host='keycloak', port=8180): Max retries exceeded with url: /realms/idlab/.well-known/openid-configuration (Caused by NameResolutionError("HTTPSConnection(host='keycloak', port=8180): Failed to resolve 'keycloak' ([Errno -3] Temporary failure in name resolution)"))
Error code   backchannel_failed
Detail       ConnectionError fetching https://keycloak:8180/realms/idlab/.well-known/openid-configuration
```

It fails at the first step because changing the settings restarted the app, so it hasn't loaded Keycloak's discovery document yet.

The app's log:

```
2026-10-21 08:35:19,955 WARNING oidc-rp event=oidc_login_failed reason=backchannel_failed error='HTTPSConnectionPool(host='"'"'keycloak'"'"', port=8180): Max retries exceeded with url: /realms/idlab/.well-known/openid-configuration (Caused by NameResolutionError("HTTPSConnection(host='"'"'keycloak'"'"', port=8180): Failed to resolve '"'"'keycloak'"'"' ([Errno -3] Temporary failure in name resolution)"))' detail='ConnectionError fetching https://keycloak:8180/realms/idlab/.well-known/openid-configuration'
```

and **Squid's log shows nothing**: no `CONNECT keycloak:8180` from the app at all. In runbooks 11 to 13 the proxy refused or tampered with the call; here the call never reached it.

The error is about DNS because the app's network, like many server networks, only resolves and routes internal names. External destinations are reachable only through the proxy, which resolves names itself. With a different network design, the same mistake shows up as `Connection timed out` (a firewall dropping the direct connection) or `Connection refused`.

How customers describe it: *"DNS is broken on the app server"* (it isn't: it was never meant to resolve that name), or *"it broke after the redeploy, but the code didn't change"*.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  proxy-bypass                   broken   proxy.env: HTTPS_PROXY=http://squid:3128 NO_PROXY=localhost,127.0.0.1,keycloak,.idlab.example (the RP's only route to keycloak is the proxy)

# The settings as the app's process actually has them (not as the config file says)
docker compose exec oidc-rp-egress printenv HTTPS_PROXY NO_PROXY
#  http://squid:3128
#  localhost,127.0.0.1,keycloak,.idlab.example

# Did the call reach the proxy? (Nothing printed: no.)
docker compose logs --since 10m squid | grep 'CONNECT keycloak'

# Ask the client library what it will do for the IdP's URL
docker compose exec oidc-rp-egress python -c "
import requests.utils as u
url = 'https://keycloak:8180/realms/idlab'
print('bypass proxy:', u.should_bypass_proxies(url, no_proxy=None), '| proxies:', u.get_environ_proxies(url))"
```

That last check is the quickest proof. With the broken settings:

```
bypass proxy: True | proxies: {}
```

and with the healthy ones:

```
bypass proxy: False | proxies: {'https': 'http://squid:3128', 'no': 'localhost,127.0.0.1'}
```

## Diagnosis

1. **No proxy log entry at all** for the failing call means the client didn't use the proxy. Compare runbooks 11 (407), 12 (403) and 13 (certificate), where Squid logs every attempt.
2. **Read the process's environment, not the deployment file.** The variables can come from the image, the compose or Kubernetes manifest, an `env_file`, a systemd unit, `/etc/environment` or the app's own config, and a later source can override an earlier one. `printenv` inside the running container (or `/proc/<pid>/environ` for a process) shows what's really in effect.
3. **How each client matches `NO_PROXY`.** It's a convention, not a standard, and clients differ:
   - Python (requests, urllib): comma-separated; an entry matches the host itself and any name ending in it (`.idlab.example` and `idlab.example` both cover `sso.idlab.example`); requests also understands CIDR ranges (`10.0.0.0/8`) for IP addresses.
   - curl: comma-separated; suffix match on names; CIDR in recent versions. It reads lowercase `http_proxy` only, but `https_proxy` or `HTTPS_PROXY`.
   - Go: comma-separated, with CIDR support.
   - Java ignores `NO_PROXY` and `HTTPS_PROXY`. It uses `-Dhttps.proxyHost`, `-Dhttps.proxyPort` and `-Dhttp.nonProxyHosts` (separated by `|`, with `*` wildcards), unless the app maps the variables itself.
   - Upper and lower case: many clients read both, but which one wins differs. Set both the same, or only one, never two different values.
4. **The opposite mistake: internal traffic sent to the proxy.** `NO_PROXY` too short is just as common. Captured in the lab with `NO_PROXY` empty: the app's own healthcheck (`https://localhost:8182/healthz`) went to Squid, which refused it, and the container stayed unhealthy:
   ```
   urllib.error.URLError: <urlopen error Tunnel connection failed: 403 Forbidden>
   ```
   ```
   1792571748.278      0 172.30.183.3 TCP_DENIED/403 3333 CONNECT localhost:8182 - HIER_NONE/- text/html
   ```
   A proxy that asks for `CONNECT localhost:...` or for an internal name it can't resolve is the giveaway. If the proxy allows such requests, internal calls instead work slowly, from the proxy's address, or appear in the proxy's logs where they shouldn't (with any tokens in their URLs).
5. **Is the IdP internal or external, from the app's point of view?** That decides where it belongs. Put it in `NO_PROXY` only if the app server can reach it directly: it resolves, it's routed, and the firewall allows it.

**Root cause, in one sentence for the customer:** the app's `NO_PROXY` setting was changed to include the identity provider's hostname, so its calls to the identity provider no longer go through the egress proxy; the app server has no direct route to the identity provider (it can't even resolve the name), so every login fails at the first step.

## Fix

1. Take the IdP back out of `NO_PROXY`. In the lab:
   ```bash
   scripts/fix.sh proxy-bypass
   ```
   Recreating the container throws away its logs, and with them the failed logins. `fix.sh` saves them first and prints where.
   By hand, save them yourself, put back `.state/oidc-rp-egress/proxy.env` from `squid/defaults/oidc-rp-egress.env` (`NO_PROXY=localhost,127.0.0.1`), then recreate the app so its process picks the change up:
   ```bash
   docker compose logs --no-log-prefix --timestamps oidc-rp-egress > oidc-rp-egress-before-fix.log
   docker compose up -d --no-deps --wait oidc-rp-egress
   ```
   Environment variables are read when a process starts. Editing the file, or exporting a variable in a shell, changes nothing for the app until it restarts.
2. Verify: `printenv NO_PROXY` in the container no longer lists `keycloak`, a login at https://LAB_HOST:8186/ works, Squid logs `TCP_TUNNEL/200 ... CONNECT keycloak:8180`, and `scripts/status.sh` shows `healthy`.

## Prevention

- **Keep `NO_PROXY` short and specific to the environment,** and document why each entry is there. Avoid copying one list across environments with different networks.
- **Include `localhost` and `127.0.0.1`** (and the app's own internal names) so health checks and sidecars never go to the proxy.
- **Test the decision, not just the connection.** After a configuration change, check whether the client will use the proxy for the IdP's URL (as with `should_bypass_proxies` above), and that the proxy logs the call.
- **Synthetic logins after every redeploy** catch this before users do.

## Questions I'd ask the customer

1. Does the error mention DNS (`Failed to resolve`, `Name or service not known`), a timeout or a refused connection, rather than a proxy status like 403 or 407?
2. Does the proxy log anything from the app server for the IdP at the time of the failure?
3. What are `HTTPS_PROXY`, `https_proxy`, `NO_PROXY` and `no_proxy` inside the running app process (not in the template)? What changed in the last deployment?
4. Is the IdP meant to be reached directly or through the proxy from this network? Does its name resolve on the app server?
5. Which HTTP client and language does the app use, and how does that client read proxy settings (environment variables, Java system properties, its own configuration)?
6. Is any client here configured with a **PAC file or WPAD** instead? PAC files decide per URL in JavaScript (`DIRECT` or `PROXY host:port`), so their `DIRECT` rules play the part of `NO_PROXY`. WPAD finds the PAC file automatically through DNS or DHCP (`http://wpad.<domain>/wpad.dat`), so a DNS or DHCP change can quietly change which traffic is proxied. Browsers usually follow PAC and WPAD; most server-side services don't. So a browser on the same server isn't a reliable test of the service's path.
