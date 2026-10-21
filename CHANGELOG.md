# Changelog

What each phase added, and why an existing lab needs `scripts/setup.sh` then `scripts/test.sh --fresh` after it. See [Upgrading an existing lab](README.md#upgrading-an-existing-lab) in the README.

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
