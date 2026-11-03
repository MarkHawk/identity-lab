# Scenarios and the tools that help

Other tools of mine that help diagnose these scenarios:

| Scenario | Runbook | What the user sees | Tool that helps |
|---|---|---|---|
| `expired-signing-cert` | [01-expired-signing-cert](../runbooks/01-expired-signing-cert.md) | SAML SP: `IdP signing certificate expired on <date>` | [token-inspector](https://github.com/MarkHawk/token-inspector), [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) |
| `clock-skew` | [02-clock-skew](../runbooks/02-clock-skew.md) | SAML SP: `Could not validate timestamp: expired. Check system clock.` | [token-inspector](https://github.com/MarkHawk/token-inspector), [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) |
| `redirect-uri-mismatch` | [03-redirect-uri-mismatch](../runbooks/03-redirect-uri-mismatch.md) | Keycloak: `Invalid parameter: redirect_uri` | [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) |
| `ldap-bind-failure` | [04-ldap-bind-failure](../runbooks/04-ldap-bind-failure.md) | Keycloak (LDAP users): `Unexpected error when handling authentication request to identity provider.` | [auth-capture-explainer](https://github.com/MarkHawk/auth-capture-explainer), [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) |
| `radius-shared-secret-mismatch` | [05-radius-shared-secret-mismatch](../runbooks/05-radius-shared-secret-mismatch.md) | NAS: `RADIUS server not responding` | [auth-capture-explainer](https://github.com/MarkHawk/auth-capture-explainer), [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) |
| `proxy-bad-gateway` | [06-proxy-bad-gateway](../runbooks/06-proxy-bad-gateway.md) | nginx: `502 Bad Gateway` | [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) |
| `proxy-gateway-timeout` | [07-proxy-gateway-timeout](../runbooks/07-proxy-gateway-timeout.md) | nginx: `504 Gateway Time-out` | [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) |
| `proxy-rate-limit` | [08-proxy-rate-limit](../runbooks/08-proxy-rate-limit.md) | nginx: `429 Too Many Requests` | [rate-limit-probe](https://github.com/MarkHawk/rate-limit-probe), [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) |
| `proxy-forwarded-headers` | [09-proxy-forwarded-headers](../runbooks/09-proxy-forwarded-headers.md) | Keycloak: `Invalid Request` | [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) |
| `proxy-header-too-large` | [10-proxy-header-too-large](../runbooks/10-proxy-header-too-large.md) | nginx: `502 Bad Gateway` instead of the login page | [identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk) |
| `proxy-auth-required` | [11-proxy-auth-required](../runbooks/11-proxy-auth-required.md) | App: `Tunnel connection failed: 407 Proxy Authentication Required` | Splunk support planned |
| `proxy-policy-block` | [12-proxy-policy-block](../runbooks/12-proxy-policy-block.md) | App: `Tunnel connection failed: 403 Forbidden` | Splunk support planned |
| `proxy-tls-interception` | [13-proxy-tls-interception](../runbooks/13-proxy-tls-interception.md) | App: `certificate verify failed: self-signed certificate in certificate chain` | Splunk support planned |
| `proxy-bypass` | [14-proxy-bypass](../runbooks/14-proxy-bypass.md) | App: `Failed to resolve 'keycloak'` | Splunk support planned |
| `redirect-loop` | [15-redirect-loop](../runbooks/15-redirect-loop.md) | Browser: `ERR_TOO_MANY_REDIRECTS` | None of these: `curl -I` and `nginx -T` (see the runbook) |
| `api-bearer-audience` | [16-api-bearer-401](../runbooks/16-api-bearer-401.md) | API: `401`, `error="invalid_token"`, audience | [token-inspector](https://github.com/MarkHawk/token-inspector) |
| `api-bearer-expired` | [16-api-bearer-401](../runbooks/16-api-bearer-401.md) | API: `401`, `error="invalid_token"`, expired | [token-inspector](https://github.com/MarkHawk/token-inspector) (with `--skew` set to the API's; see the runbook) |
| `proxy-maintenance` | [17-service-unavailable](../runbooks/17-service-unavailable.md) | Proxy: `Sign-in is down for planned maintenance` (503) | Splunk support planned. Meanwhile, the proxy's access log: `upstream=-` on the 503s |
| `client-cert-missing` | [18-client-cert](../runbooks/18-client-cert.md) | nginx: `400`, `No required SSL certificate was sent` | None of these: `curl -v`, `openssl s_client` and the proxy's `ssl_client_verify` (see the runbook) |
| `client-cert-expired` | [18-client-cert](../runbooks/18-client-cert.md) | nginx: `400`, `The SSL certificate error` | None of these: `openssl x509` and `openssl verify -purpose sslclient` on the client's certificate (see the runbook) |
| `cors-blocked` | [19-cors-blocked](../runbooks/19-cors-blocked.md) | Page: `Failed to fetch`; console: `blocked by CORS policy` | None of these: the browser's developer console and Network tab, and `curl -H 'Origin: ...'` (see the runbook) |

- **[token-inspector](https://github.com/MarkHawk/token-inspector)** decodes a SAML response or JWT offline and explains the likely cause, such as an expired or rotated signing certificate (01), clock skew (02), or an access token issued for another API or past its expiry (16).
- **[auth-capture-explainer](https://github.com/MarkHawk/auth-capture-explainer)** reads a RADIUS or LDAP packet capture offline and explains the likely cause, such as a NAS whose shared secret differs from the server's (05) or a directory service account that can't bind (04).
- **[rate-limit-probe](https://github.com/MarkHawk/rate-limit-probe)** shows whether a 429 comes from the client retrying too early, or from the API's limit or headers being wrong (08).
- **[identity-support-splunk](https://github.com/MarkHawk/identity-support-splunk)** is a Splunk app that shows when each failure started, who is affected and the likely cause, with a link to the runbook (01 to 10).
- **[triage-assistant](https://github.com/MarkHawk/triage-assistant)** reads a ticket (and optionally the lab's logs), finds the matching runbook, and drafts a diagnosis and customer reply, or asks clarifying questions when the ticket doesn't say enough (01 to 19).
