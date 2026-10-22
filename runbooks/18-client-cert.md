# 18 · Mutual TLS: 400 from nginx, no client certificate (496) or a bad one (495)

| | |
|---|---|
| **Protocol** | TLS with client authentication (mutual TLS) between a client and the nginx reverse proxy. nginx asks for a client certificate during the handshake and checks it against the CA it trusts for clients, here the lab CA (`ssl_verify_client on`, `ssl_client_certificate`). No user, password or token is involved: the certificate *is* the client's identity. |
| **Blast radius** | One client (the partner system with that certificate) on the one route that requires it (`https://LAB_HOST:8189`). Other clients with valid certificates, and every other route through the same proxy, are fine. |
| **Typical trigger** | **No certificate (496):** a redeploy or migration that left out the client's certificate and key (a secret, volume or keystore not mounted), a client library upgrade that stopped sending it, an HTTP client configured without it, a TLS-inspecting proxy between client and server. **Bad certificate (495):** the certificate expired and nobody renewed it; it was renewed under a different CA (or self-signed) than the server trusts; the server's trusted client CA was changed; the certificate lacks the client-authentication purpose. |
| **Lab** | `scripts/break.sh client-cert-missing` · `scripts/fix.sh client-cert-missing` (deletes the client's certificate and key from `.state/mtls-client/`) and `scripts/break.sh client-cert-expired` · `scripts/fix.sh client-cert-expired` (replaces them with a certificate from the lab CA that expired yesterday). nginx isn't touched in either. |

## Symptom

The partner system calls `https://LAB_HOST:8189/` as it always has. **The TLS handshake succeeds**, and nginx then answers with its plain error page. In both cases the HTTP status is **400 Bad Request**, not 495 or 496. Only the page's title and second line differ.

With no certificate (`client-cert-missing`):

```
HTTP/1.1 400 Bad Request
Server: nginx
Content-Type: text/html
Connection: close

<html>
<head><title>400 No required SSL certificate was sent</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<center>No required SSL certificate was sent</center>
<hr><center>nginx</center>
</body>
</html>
```

With an expired certificate (`client-cert-expired`):

```
<head><title>400 The SSL certificate error</title></head>
...
<center><h1>400 Bad Request</h1></center>
<center>The SSL certificate error</center>
```

When it's healthy, the route answers with what nginx verified:

```
{"client_certificate":"accepted","subject":"CN=partner-client","not_after":"Nov 23 18:32:36 2027 GMT"}
```

**495 and 496 are nginx's internal codes** for these two cases (with 497, *plain HTTP sent to an HTTPS port*). They never appear on the wire. The client and the standard access log both see `400`, so a dashboard of 4xx responses shows these as ordinary bad requests. The internal codes are only visible where nginx uses them: `error_page 495` / `error_page 496`, which can replace the page.

The lab's access log line for this route records what nginx made of the certificate, in `ssl_client_verify`:

```
172.30.182.1 "GET / HTTP/1.1" 400 230 host=idlab.home:8189 client_dn="-" client_not_after="-" ssl_client_verify=NONE
172.30.182.1 "GET / HTTP/1.1" 400 208 host=idlab.home:8189 client_dn="CN=partner-client" client_not_after="Oct 21 18:37:38 2026 GMT" ssl_client_verify=FAILED:certificate has expired
172.30.182.1 "GET / HTTP/1.1" 200 103 host=idlab.home:8189 client_dn="CN=partner-client" client_not_after="Nov 23 18:32:36 2027 GMT" ssl_client_verify=SUCCESS
```

and nginx says why in its error log, **at `info` level**, which a default `error_log ... error` hides:

```
2026/10/22 18:37:38 [info] 13#13: *5 client sent no required SSL certificate while reading client request headers, client: 172.30.182.1, server: , request: "GET / HTTP/1.1", host: "idlab.home:8189"
2026/10/22 18:37:38 [info] 13#13: *6 client SSL certificate verify error: (10:certificate has expired) while reading client request headers, client: 172.30.182.1, server: , request: "GET / HTTP/1.1", host: "idlab.home:8189"
```

In a browser, nginx's 400 page looks the same. If the browser has certificates installed, it first asks which one to send, offering only those issued by a CA in the server's request (see *Where to look*). Choosing none, or having none, gives the first page.

How customers describe it: *"Your API returns 400 Bad Request, but we haven't changed anything,"* often after a redeploy on their side or on the date their certificate expired. *"The TLS connection works"* is true and misleading.

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  client-cert-missing            broken   the client has no certificate in .state/mtls-client
#  client-cert-expired            broken   the client certificate does not verify: error 10 at 0 depth lookup: certificate has expired (subject=CN=partner-client notAfter=Oct 21 ...)

# What nginx made of the certificate, request by request
docker compose logs proxy | grep 'host=[^ ]*:8189'
docker compose logs proxy | grep -E 'no required SSL certificate|client SSL certificate verify error'

# The request as the client makes it. -v shows the handshake: the server asks
# (Request CERT), and the client proves it holds a key (OUT ... CERT verify)
# only if it sent a certificate. Without one, there is no (OUT) CERT verify line.
curl -sS -v --cacert certs/ca.crt --cert .state/mtls-client/client.crt --key .state/mtls-client/client.key \
  https://LAB_HOST:8189/ 2>&1 | grep -E 'Request CERT|\(OUT\).*(Certificate|CERT verify)|^< HTTP'
#  * TLSv1.3 (IN), TLS handshake, Request CERT (13):
#  * TLSv1.3 (OUT), TLS handshake, Certificate (11):
#  * TLSv1.3 (OUT), TLS handshake, CERT verify (15):
#  < HTTP/1.1 400 Bad Request

# Which CAs the server accepts client certificates from (it says so in the handshake)
openssl s_client -connect LAB_HOST:8189 -CAfile certs/ca.crt </dev/null 2>/dev/null | grep -A1 'Acceptable client certificate CA names'
#  Acceptable client certificate CA names
#  O=identity-lab, CN=identity-lab Local CA

# The client's certificate: who issued it, its dates, and its purpose
openssl x509 -in .state/mtls-client/client.crt -noout -subject -issuer -startdate -enddate -ext extendedKeyUsage
#  subject=CN=partner-client
#  issuer=O=identity-lab, CN=identity-lab Local CA
#  notAfter=Oct 21 18:37:38 2026 GMT                <- in the past
#  X509v3 Extended Key Usage:
#      TLS Web Client Authentication

# The check nginx makes, done locally
openssl verify -CAfile certs/ca.crt -purpose sslclient .state/mtls-client/client.crt
#  error 10 at 0 depth lookup: certificate has expired
```

In a real case you rarely have the client's private key. Ask for its **certificate** (public, safe to send). With it and the server's client CA bundle, `openssl x509` and `openssl verify` answer most cases without the client's help.

## Diagnosis

1. **The page tells you which half failed.** *No required SSL certificate was sent* (496): the client didn't present one at all. *The SSL certificate error* (495): it presented one, and nginx rejected it. These need different fixes from different people: the first is the client's configuration, the second is the certificate itself or the server's trust.
2. **`ssl_client_verify` and the `info` line give the reason.** `NONE` means no certificate. `FAILED:<reason>` uses OpenSSL's wording, the same as `openssl verify`. These were captured in this lab:

   | `ssl_client_verify` / error log | Meaning |
   |---|---|
   | `NONE` / `client sent no required SSL certificate` | No certificate in the handshake. **client-cert-missing.** |
   | `FAILED:certificate has expired` / `(10:certificate has expired)` | Past its `notAfter`. **client-cert-expired.** |
   | `FAILED:self-signed certificate` / `(18:self-signed certificate)` | Not issued by any CA, so not by the one nginx trusts. |
   | `SUCCESS` | Accepted. Any later failure is the application's, not TLS. |

   Other reasons you will meet in real cases: `unable to get local issuer certificate` (issued by a CA the server doesn't trust, or the intermediate isn't sent), `certificate is not yet valid` (a clock or `notBefore` problem), `unsupported certificate purpose` (the certificate lacks the clientAuth extended key usage), `certificate revoked` (with a CRL configured).
3. **Why the handshake succeeds and HTTP fails.** With `ssl_verify_client on`, nginx deliberately lets the TLS handshake finish when verification fails, then refuses at the HTTP level, so it can send a page and log the request. Other servers and load balancers end the handshake instead. The client then sees a TLS alert such as `alert certificate required`, `bad certificate` or `unknown ca`, not an HTTP response, and the server's access log has no line at all.
4. **"No certificate" can mean the client had one and didn't send it.** Browsers, and some TLS libraries, only offer certificates issued by one of the CA names the server asks for (the *Acceptable client certificate CA names* above). A browser whose only certificate comes from another CA sends none, which nginx logs as `NONE`, not as an untrusted certificate. curl and most OpenSSL-based clients send whatever certificate they are configured with, so they get the 495 instead. A TLS-inspecting proxy between client and server also turns any certificate into `NONE`, because it starts a new TLS connection without the client's certificate.
5. **Look at the dates first.** Client certificates often have short lifetimes, are installed by hand on partner systems and aren't monitored. "Nothing changed" on a date that matches `notAfter` is the commonest version of this ticket.

**Root cause, in one sentence for the customer:**
- missing: *your system connected to the mutual-TLS endpoint without presenting its client certificate (it wasn't included in the new deployment), so the server rejected every request with 400.*
- expired: *your client certificate expired on <date>; the server only accepts valid certificates from its partner CA, so it rejects every request with 400 until the certificate is renewed.*

## Fix

1. Give the client a valid certificate from the CA the server trusts. In the lab, for either scenario:
   ```bash
   scripts/fix.sh client-cert-missing     # or client-cert-expired
   ```
   That copies the healthy certificate and key from `certs/mtls-client.*` back to `.state/mtls-client/`. In real life:
   - **missing:** restore the certificate and key to the client's deployment (the secret, volume or keystore), and check its HTTP client really is configured to send them.
   - **expired:** have the partner request a new certificate from the CA you trust for clients, and install it, with its key, on their side.
2. Verify: the route answers `{"client_certificate":"accepted",...}`, the access log shows `ssl_client_verify=SUCCESS` with the new `client_not_after`, and `scripts/status.sh` shows both scenarios `healthy`.

Don't fix it by setting `ssl_verify_client optional_no_ca` or `off`, by trusting a CA just because the partner's new certificate came from it, or by accepting expired certificates. Each one removes the only thing that identifies the client.

## Prevention

- **Monitor client certificate expiry on both sides.** The server can log `$ssl_client_v_end` (as here) or `$ssl_client_v_remain` and alert when a known client's certificate has less than 30 days left. The client should monitor its own.
- **Log `$ssl_client_verify` and `$ssl_client_s_dn`** on every mutual-TLS route, and keep the error log at `info` for it, or this whole class of failure shows up only as anonymous 400s.
- **Agree on renewal with partners before the first certificate is issued:** who renews, how far ahead, and who is told. Automate it where you can.
- **Treat the certificate and key as part of the deployment.** Check that a new release can still complete a mutual-TLS call before it takes traffic.
- **Optionally, make the error page say which case it is** (`error_page 495 /cert-invalid.html; error_page 496 /cert-missing.html;`) and who to contact, so the first ticket already has the answer.

## Questions I'd ask the customer

1. What exactly does the error page or body say: *No required SSL certificate was sent* or *The SSL certificate error*? Do you get an HTTP response at all, or a TLS error?
2. Can you send us the client certificate (the public certificate only, never the key)? What are its issuer and `notAfter` date?
3. Did anything change on your side: a redeploy, a new server or container image, a library upgrade, a new proxy or firewall that inspects TLS?
4. How does your system load the certificate and key (file paths, keystore, secret manager)? Are they present in the running deployment?
5. Is it every request from your system, or only from some servers or instances?
6. When was the certificate last renewed, and by whom? Was the new one issued by the same CA as before?
