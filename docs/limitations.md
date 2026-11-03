# Known limitations

What the lab doesn't do, or does differently from production.

- **A rebuild can install newer apt packages than the last one.** apt packages aren't pinned (see [design decisions](design-decisions.md)), so an image rebuilt without the cache gets the distribution's current security updates, and two machines can build slightly different images from the same commit.
- **The clock-skew scenario also affects the SAML SP behind the proxy.** Both SAML SPs read the same `.state/saml-sp/` files, the pinned IdP certificate and the libfaketime offset, so while `clock-skew` is broken a SAML login through `:8184` fails too. `scripts/test.sh` doesn't check the proxied SP during that scenario. `expired-signing-cert` changes the shared pinned certificate in the same way.
- **One rate-limit bucket for every browser.** All browser traffic reaches the proxy from the Docker gateway's address, so `proxy-rate-limit` limits every user together, and a `rate-limit-probe` run shares the bucket with your own logins for a few seconds.
- **The egress proxy offers Basic authentication only.** Corporate proxies often use NTLM or Kerberos (Negotiate); runbook 11 describes what those look like, but the lab doesn't reproduce them.
- **Squid's first build is slow.** It's compiled from source: about 8 minutes on 4 cores, more on a 2-core codespace. Later builds use the cache.
- **The OIDC app never refreshes its access token.** That's deliberate, for `api-bearer-expired`: after Keycloak's default 5 minutes, **Call the API** fails as expired even on a healthy lab until you log in again.
- **The mutual-TLS route has no upstream.** nginx answers it itself, with the certificate it verified, because the scenarios are about the TLS layer. A real one would pass the verified identity on to an app (as `X-SSL-Client-*` headers, trusted only from the proxy).
- **CORS: one allowed origin, and a permissive preflight.** The API allows one origin, the direct OIDC app's, and answers every preflight positively, as a gateway in front of it might. So the lab reproduces a blocked response, not a failed preflight; runbook 19 describes that case.
- **The OIDC app's debug page hands its access token to its own script** (through `/debug/access-token`) for the browser's API call. A real single-page app gets its own tokens; a server-side app shouldn't expose them to the page.
- **Single-worker apps.** Each app runs one gunicorn worker with an in-memory store for decoded logins. That's fine for a lab, not for production.
- **MFA logins in the tests wait for a fresh code.** Keycloak refuses a code that has been used, so each of grace's test logins waits for the authenticator's next 30-second step. That adds a few minutes to a run.
- **ivan's setup codes aren't in the leak scan.** `e2e.py` makes them in the browser container from the key on the setup page, so `scripts/test.sh` never sees them. That key is scrubbed from the saved page and checked for there; the codes made from it are not searched for in the logs.
- **One authenticator, and its secret is in its environment.** The authenticator container gets grace's TOTP secret as an environment variable, as the other containers get theirs, so `docker inspect` shows it to anyone who can run Docker on the lab host. A real phone keeps it in secure storage.
- **Tested platform.** The lab has only been tested on x86_64 Linux.
- **Codespaces: no browser logins at the forwarded URLs.** In a codespace, use `scripts/test.sh`, or forward the ports to your own `localhost` (see the [Codespaces guide](codespaces.md#2-open-it-in-desktop-vs-code)).
- **FreeRADIUS's TLS warning.** At start, FreeRADIUS warns that `libldap is using GnuTLS, while FreeRADIUS is using OpenSSL`. That's how Ubuntu builds the image's libldap. LDAPS to the directory works and is tested, but the warning is real for production; there, use a libldap built against OpenSSL.
- **RADIUS is PAP only.** The NAS sends PAP over the internal network. There's no EAP (802.1X), RadSec or accounting scenario.
- **Not production configuration.** Demo users share one password, the directory and the RADIUS server each run as a single server with no replication or failover, Keycloak's bootstrap admin is used for the scenario scripts, and the SAML SP doesn't do Single Logout.
