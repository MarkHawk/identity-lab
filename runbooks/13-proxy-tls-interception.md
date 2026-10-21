# 13 · Egress proxy: TLS interception with a CA the client doesn't trust

| | |
|---|---|
| **Protocol** | HTTPS from an app server to the IdP through a forward ("egress") proxy that inspects TLS: also called "SSL inspection", "SSL bump", "TLS break and inspect" or "HTTPS decryption". The proxy ends the client's TLS session, opens its own to the server, and shows the client a certificate it has minted for that server, signed by the proxy's own CA. Here the client is the OIDC RP's back channel: discovery, token, userinfo and JWKS. |
| **Blast radius** | Every client of that proxy that doesn't trust the proxy's CA: typically servers, containers and appliances, which have their own CA bundles and miss the corporate CA that IT pushes to staff laptops. Here, every login on the OIDC RP at `https://LAB_HOST:8186`. Browsers and the direct OIDC RP (`:8182`) don't use the proxy and keep working. |
| **Typical trigger** | TLS inspection switched on or extended to a new network or category; a new inspection CA certificate (renewal or a new appliance); a new container image or runtime whose CA bundle doesn't include the corporate CA; or `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` or a Java truststore set to a file that has one of the CAs but not the other. |
| **Lab** | `scripts/break.sh proxy-tls-interception` · `scripts/fix.sh proxy-tls-interception` (turns on `ssl-bump` on Squid's port in `.state/squid/tls.conf`, with the inspection CA `certs/squid-ca.crt`, and runs `squid -k reconfigure`) |

## Symptom

Go to https://LAB_HOST:8186/, click **Log in with OIDC** and sign in as `alice`. Back at the app, it shows **OIDC login failed**:

```
HTTPSConnectionPool(host='keycloak', port=8180): Max retries exceeded with url: /realms/idlab/protocol/openid-connect/token (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain (_ssl.c:1032)')))
Error code   backchannel_failed
Detail       SSLError
```

As in runbooks 11 and 12, if the app has restarted since its last login, it fails straight after **Log in**, fetching `/.well-known/openid-configuration`.

`self-signed certificate in certificate chain` means the chain the app received ends in a self-signed root it doesn't trust: here, the proxy's inspection CA, which Squid sends along with the certificate it minted. If the proxy sends only the minted certificate, the same problem reads `unable to get local issuer certificate`. Other clients describe it as:
- Java: `PKIX path building failed ... unable to find valid certification path to requested target`
- curl: `SSL certificate problem: self-signed certificate in certificate chain`
- Node.js: `SELF_SIGNED_CERT_IN_CHAIN`

The app's log:

```
2026-10-21 08:32:24,664 WARNING oidc-rp event=oidc_login_failed reason=backchannel_failed error='HTTPSConnectionPool(host='"'"'keycloak'"'"', port=8180): Max retries exceeded with url: /realms/idlab/protocol/openid-connect/token (Caused by SSLError(SSLCertVerificationError(1, '"'"'[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain (_ssl.c:1032)'"'"')))' detail=SSLError
```

Squid's access log shows a **successful** CONNECT (`/200`), but not a tunnel:

```
1792571544.664     27 172.30.183.3 NONE_NONE/200 0 CONNECT keycloak:8180 - HIER_DIRECT/172.18.0.2 -
```

and its own log records the client rejecting its certificate:

```
2026/10/21 08:32:24| ERROR: Cannot accept a TLS connection
    problem: failure
    error detail: SQUID_TLS_ERR_ACCEPT+TLS_LIB_ERR=A000418+TLS_IO_ERR=1
    current master transaction: master67
```

`TLS_LIB_ERR=A000418` is an OpenSSL error code:

```bash
docker compose exec squid openssl errstr A000418
#  error:0A000418:SSL routines::tlsv1 alert unknown ca
```

The client sent the TLS alert *unknown CA*: it didn't trust the issuer of the certificate Squid presented. Compare a healthy tunnel, where Squid never touches the TLS: `TCP_TUNNEL/200 9936 CONNECT keycloak:8180 ... HIER_DIRECT/...`.

How customers describe it: *"Our app suddenly says the IdP's certificate is invalid, but the IdP's certificate is fine in the browser."* Both observations are true: the browser isn't going through the inspecting proxy, or its machine trusts the corporate CA.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  proxy-tls-interception         broken   tls.conf: http_port 3128 ssl-bump tls-cert=/etc/idlab/squid-ca.crt ... ssl_bump peek step1 ssl_bump bump all (the RP doesn't trust the proxy's inspection CA)

# The proxy's logs: CONNECTs that aren't tunnels, and TLS accept errors
docker compose logs squid | grep -E 'NONE_NONE/200|Cannot accept a TLS|TLS_LIB_ERR'

# Which CA bundle the app verifies against
docker compose exec oidc-rp-egress printenv REQUESTS_CA_BUNDLE HTTPS_PROXY
#  /etc/idlab/ca.crt
#  http://squid:3128
```

The decisive test: **who issued the certificate the app is actually shown**, through the proxy, on the app's own network path. Verification is off only so the chain can be printed:

```bash
docker compose exec oidc-rp-egress python -c '
import socket, ssl
from cryptography import x509
s = socket.create_connection(("squid", 3128))
s.sendall(b"CONNECT keycloak:8180 HTTP/1.1\r\nHost: keycloak:8180\r\n\r\n"); s.recv(4096)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
for c in ctx.wrap_socket(s, server_hostname="keycloak").get_unverified_chain():
    c = x509.load_der_x509_certificate(c)
    print("subject:", c.subject.rfc4514_string(), "| issuer:", c.issuer.rfc4514_string())'
#  subject: CN=idlab.home | issuer: CN=identity-lab Egress Inspection CA,O=identity-lab egress proxy
#  subject: CN=identity-lab Egress Inspection CA,O=identity-lab egress proxy | issuer: CN=identity-lab Egress Inspection CA,O=identity-lab egress proxy
```

and compare with Keycloak's real certificate:

```bash
openssl x509 -in certs/tls.crt -noout -subject -issuer
#  subject=O=identity-lab, CN=idlab.home
#  issuer=O=identity-lab, CN=identity-lab Local CA
```

The subject and names were copied ("mimicked") from Keycloak's certificate, so the hostname check would pass. Only the issuer gives it away. When you look at a certificate in a support session, always read the **issuer**, not just the name and the expiry date.

## Diagnosis

1. **Is the certificate the server's, or the proxy's?** Fetch the chain the client sees through the proxy, as above, or ask the customer to run `openssl s_client -proxy <proxy>:<port> -connect <idp-host>:443 -showcerts` from the affected server. An issuer that names a proxy, a security vendor or "Inspection" / "Decryption" / "Forward Trust" means interception.
2. **Did the IdP's certificate change?** Usually not. If a browser that doesn't go through the proxy (or the direct app on `:8182`) still sees the IdP's own issuer, the server is fine and the proxy changed.
3. **Is it trust, or a hostname problem?** `self-signed certificate in certificate chain` and `unable to get local issuer certificate` are trust problems. `Hostname mismatch` or `doesn't match` would point to a proxy that mints certificates badly or to the wrong hostname being used.
4. **Why doesn't the app trust the corporate CA when the laptops do?** Laptops get the corporate CA from device management. Containers use the CA bundle in their image, or the file in `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` or a Java truststore. Note that `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` **replace** the default bundle; they don't add to it. Pointing one at the corporate CA alone breaks every other HTTPS call the app makes. This app's bundle is the lab CA only, which is why the proxy's CA is unknown to it.
5. **Should the IdP be inspected at all?** The back channel carries the client secret, authorisation codes, access, ID and refresh tokens. An inspecting proxy sees all of them in clear and may log them. Most inspection policies exempt identity providers, banking and health sites for that reason. Some IdP clients also pin the IdP's certificate or key, and break under inspection however the CAs are set up.

**Root cause, in one sentence for the customer:** TLS inspection was turned on at the egress proxy, so the application servers now receive certificates signed by the proxy's own CA instead of the identity provider's certificate; the servers don't trust that CA, reject every connection to the identity provider, and all logins on those apps fail.

## Fix

1. Turn inspection off for this path. In the lab:
   ```bash
   scripts/fix.sh proxy-tls-interception
   ```
   By hand, put back `.state/squid/tls.conf` from `squid/defaults/tls.conf` (a plain `http_port 3128`), then:
   ```bash
   docker compose exec squid squid -k parse -f /etc/squid/squid.conf
   docker compose exec squid squid -k reconfigure -f /etc/squid/squid.conf
   ```
2. Verify: a login at https://LAB_HOST:8186/ works, Squid logs `TCP_TUNNEL/200 ... CONNECT keycloak:8180`, and `scripts/status.sh` shows `healthy`.

In a real deployment there are two lasting fixes, both tried in this lab with inspection on:

- **Exempt the IdP from inspection (recommended).** In Squid, splice it by the name in the TLS handshake before the general bump rule:
  ```
  acl idp_hosts ssl::server_name keycloak
  ssl_bump peek step1
  ssl_bump splice idp_hosts
  ssl_bump bump all
  ```
  With that in place, the login worked and Squid logged a real tunnel again: `TCP_TUNNEL/200 3607 CONNECT keycloak:8180 - HIER_DIRECT/172.18.0.2 -`. Commercial proxies call this a "do not decrypt" or "bypass" list.
- **Make the client trust the inspection CA as well.** A bundle with both CAs verifies; the lab CA alone doesn't:
  ```
  lab CA only -> SSLError
  lab CA + inspection CA -> 200
  ```
  Add the corporate CA to the image's trust store (for Debian-based images, copy it into `/usr/local/share/ca-certificates/` and run `update-ca-certificates`), or point `REQUESTS_CA_BUNDLE` at a file containing **all** the CAs the app needs. This works, but it lets the proxy read the app's tokens and secrets.

Don't fix it with `verify=False`, `-k`, `NODE_TLS_REJECT_UNAUTHORIZED=0` or a "trust all certificates" option. That stops the app from detecting a real man-in-the-middle, which is exactly what certificate checks are for.

## Prevention

- **Keep a do-not-inspect list for identity providers** and other endpoints that carry credentials, agreed between the security and identity teams.
- **Ship the corporate CA in server and container base images** if inspection applies to them, and test images against the inspecting proxy before rollout.
- **Treat a CA change on the proxy as a change for every server behind it,** with notice and a test window, like the IdP's own certificate rollover.
- **Monitor the login path through the proxy,** and alert on `TLS_LIB_ERR` accept errors from server networks in the proxy's log.

## Questions I'd ask the customer

1. What exactly does the error say: `self-signed certificate in certificate chain`, `unable to get local issuer certificate`, `PKIX path building failed`, or a hostname mismatch?
2. From the affected server, through the proxy, who is the **issuer** of the certificate presented for the IdP (`openssl s_client -proxy ... -showcerts`)? Is it the IdP's CA or a proxy or security vendor?
3. Was TLS inspection recently enabled, extended, or given a new CA certificate?
4. Which CA bundle does the app use: the OS store, a bundle in the image, `REQUESTS_CA_BUNDLE` or `SSL_CERT_FILE`, a Java truststore?
5. Is the IdP on the proxy's do-not-inspect list? Should it be?
6. How does the app server choose its proxy: `HTTPS_PROXY` and `NO_PROXY`, Java system properties, an app setting, or a **PAC file or WPAD**? Browsers often follow a PAC file that sends some traffic `DIRECT` or to a non-inspecting proxy, and staff laptops trust the corporate CA anyway. So a browser test can't tell you whether the service's path is inspected.
