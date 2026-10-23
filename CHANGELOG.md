# Changelog

What each phase added, and why an existing lab needs `scripts/setup.sh` then `scripts/test.sh --fresh` after it. See [Upgrading an existing lab](README.md#upgrading-an-existing-lab) in the README.

## Scenario 14 keeps its evidence (2026-10-23)

**Changed:** `scripts/break.sh proxy-bypass` and `scripts/fix.sh proxy-bypass` recreate `oidc-rp-egress`, which used to drop the broken container's logs, failed logins included. They now save them first to `.state/oidc-rp-egress/logs/<UTC time>/logs/oidc-rp-egress.log` (`docker logs --timestamps`, newest 5 kept). That's the layout identity-support-splunk's `hec_send.py replay` reads. `scripts/test.sh` checks that the fix's saved log has the `backchannel_failed` line. Runbook 14 and the walkthrough's side ticket say so.

**Why the upgrade steps:** none. The scripts create the folder the next time they recreate the container.

## Phase 3, Part C, round two: 503, mutual TLS and CORS (2026-10-22)

**Added:**

- A mutual-TLS route on the reverse proxy, port 8189 (`PROXY_MTLS_PORT`). nginx accepts only clients with a certificate from the lab CA (`ssl_verify_client on`) and answers itself; its log line carries `ssl_client_verify`, and its error log is at `info`, where nginx says why it refused a certificate. A partner client certificate, `certs/mtls-client.*`, with the client's own copy in `.state/mtls-client/`.
- CORS in the API, and **Call the API from the browser** on the direct OIDC app's debug page: a cross-origin call from `https://LAB_HOST:8182`. The API answers preflights for any origin, standing in for a gateway, and sets its own `Access-Control-Allow-Origin` on real responses from `.state/api/cors-allow-origin`. `api_request_ok` now also logs the request's `Origin` and that header.
- Scenario 17, `proxy-maintenance` (503 from maintenance mode left on); scenario 18 in two variants, `client-cert-missing` (nginx 496) and `client-cert-expired` (495); scenario 19, `cors-blocked`. Runbooks 17, 18 and 19.
- Tests: the API's preflight, the mutual-TLS route with and without a certificate (curl and Chromium, through Playwright's client certificates), the browser's cross-origin API call with its console messages, the four new scenarios, and that no private key appears in any container's log or `test.log`.

**Changed:** port 8189 is now used, so all ten lab ports are taken. The Codespaces dev container forwards it too.

**Why the upgrade steps:**

- `scripts/setup.sh` adds `PROXY_MTLS_PORT=8189` to your existing `.env`, issues the partner client certificate, and writes `.state/mtls-client/`, `.state/api/cors-allow-origin` and the proxy's new `kc-maintenance.conf`. Compose refuses to start until the new `.env` value exists.
- `scripts/test.sh` (no `--fresh` needed) rebuilds the API, OIDC app and tests images, and recreates the proxy for its new port. Nothing new is stored in Keycloak's database.

## Log changes (2026-10-22)

**Changed:** the API's `api_token_rejected` and `api_request_ok` lines now carry the token's `iat` next to its `exp`, so a log search can compute the lifetime the IdP gave it (`exp - iat`). `scripts/test.sh` checks for both.

**Changed:** the reverse proxy's access and error logs now also mask `nonce`, `code_challenge`, `Signature` (on SAML redirect-binding messages), and Keycloak's `session_code` and `client_data` as `***`, as they already did `code` and `state`. `client_data` is base64 JSON that holds the OAuth state. `scripts/test.sh` fails if an unmasked value of any of them appears in any container's log, and checks that the proxy's log holds each of them masked.

**Why the upgrade steps:** `scripts/test.sh` rebuilds the API's image and recreates its container. The proxy reads `proxy/mask.awk` from a bind mount only when it starts, so run `docker compose up -d --force-recreate proxy` (or `scripts/test.sh --fresh`). A plain restart isn't enough: it keeps the container's log, whose older lines were written unmasked and fail the new check.

## Phase 3, Part C, round one: redirect loop and API bearer 401s (2026-10-22)

**Added:**

- `oidc-rp-edge`, a fourth copy of the OIDC app, published by the reverse proxy on port 8187. TLS ends at the proxy and the app gets plain HTTP, trusts `X-Forwarded-Proto` from one hop, and forces HTTPS.
- An API (resource server, `apps/api`) on port 8188 that accepts Keycloak access tokens and answers failures with RFC 6750 `WWW-Authenticate` challenges. The direct OIDC app calls it (**Call the API**), and shows the raw token on request at `/debug/access-token`, for token-inspector.
- Scenario 15, `redirect-loop`, and scenario 16 in two variants, `api-bearer-audience` and `api-bearer-expired`, with runbooks 15 and 16.
- Tests for the edge app, the API's challenges, and that no JWT appears in any container's log, saved page or `test.log`. The access loggers also mask `access_token=` in query strings.

**Why the upgrade steps:**

- `scripts/setup.sh` adds the ports `PROXY_EDGE_RP_PORT=8187` and `API_PORT=8188` and the `oidc-rp-edge` client secret (`OIDC_EDGE_CLIENT_SECRET`) to your existing `.env`. It reissues the TLS certificate with the name `api`, and writes the proxy's new `edge-location.conf` to `.state/proxy/`. Compose refuses to start until the new `.env` values exist.
- `scripts/test.sh --fresh`: Keycloak's `oidc-rp-edge` client and the `idlab-api` audience mapper on `oidc-rp` are created at realm import, which only happens when the Keycloak database is new.

## Restart fixes (2026-10-22)

**Fixed:** Squid no longer loops on "FATAL: Squid is already running" after its container restarts: `/tmp`, where it keeps its PID file, is now a tmpfs that starts empty, and `scripts/test.sh` restarts Squid and runs scenario 11 again to prove it.

**Fixed:** the nginx reverse proxy no longer returns 502 for up to 10 seconds after `docker compose up` recreates Keycloak or an app it fronts: it now restarts with them (`depends_on` with `restart: true`), so it starts with their new addresses.

**Fixed:** image builds no longer fail when Debian or Ubuntu replace a package version: CI started failing on 22 Oct when Ubuntu replaced the pinned `libnss3-tools` in the tests image. apt packages in every Dockerfile now follow the distribution's security updates; base images stay pinned by tag and digest.

## Phase 3, Part B: Squid egress proxy (2026-10-21)

**Added:** a Squid 7.7 egress (forward) proxy, built from source, on a new internal network; `oidc-rp-egress`, a third copy of the OIDC app on port 8186 whose calls to Keycloak can only go through Squid; scenarios 11 to 14 (`proxy-auth-required`, `proxy-policy-block`, `proxy-tls-interception`, `proxy-bypass`) with runbooks; and a test that no secret from `.env` appears in any container's log.

**Why the upgrade steps:**

- `scripts/setup.sh` adds port 8186, the `oidc-rp-egress` client secret (`OIDC_EGRESS_CLIENT_SECRET`) and the egress proxy's password (`EGRESS_PROXY_PASSWORD`) to your existing `.env`. It creates the proxy's own inspection CA in `certs/squid-ca.*`, and writes the egress proxy's settings to `.state/squid/` and `.state/oidc-rp-egress/`.
- `scripts/test.sh --fresh`: Keycloak's `oidc-rp-egress` client is created at realm import, which only happens when the Keycloak database is new.
- The first build compiles Squid, which takes about 8 minutes on 4 cores.

## Phase 3, Part A: nginx reverse proxy (2026-10-20)

**Added:** an nginx reverse proxy publishing Keycloak and a second copy of each app on ports 8183 to 8185, with Keycloak taking its port and scheme from the request; scenarios 6 to 10 (`proxy-bad-gateway`, `proxy-gateway-timeout`, `proxy-rate-limit`, `proxy-forwarded-headers`, `proxy-header-too-large`) with runbooks.

**Why the upgrade steps:**

- `scripts/setup.sh` adds the proxy's ports and the `oidc-rp-proxied` client secret (`OIDC_PROXIED_CLIENT_SECRET`) to your existing `.env`. It reissues the TLS certificate with the name `proxy`, and writes the proxy's settings to `.state/proxy/`.
- `scripts/test.sh --fresh`: Keycloak's clients for the apps behind the proxy are created at realm import, which only happens when the Keycloak database is new.

## Phase 2: OpenLDAP directory and FreeRADIUS (2026-10-13 to 2026-10-14)

**Added:** an OpenLDAP directory that Keycloak federates users from; a FreeRADIUS server and a NAS that authenticate the same directory users; scenarios 4 and 5 (`ldap-bind-failure`, `radius-shared-secret-mismatch`) with runbooks; and a dev container for GitHub Codespaces.

**Why the upgrade steps:**

- `scripts/setup.sh` adds the new secrets (`LDAP_ADMIN_PASSWORD`, `LDAP_BIND_PASSWORD`, `RADIUS_LDAP_BIND_PASSWORD`, `RADIUS_SECRET`) and the directory's certificate (`certs/ldap.*`) to your existing `.env` and `certs/`.
- `scripts/test.sh --fresh`: the LDAP federation is created at realm import, which only happens when the Keycloak database is new. The directory's `radius-svc` account is created when the directory is first seeded.
