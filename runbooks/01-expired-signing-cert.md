# 01 · Expired IdP signing certificate (SAML)

| | |
|---|---|
| **Protocol** | SAML 2.0 (HTTP-POST response) |
| **Blast radius** | Every user of every SP that pinned this certificate. Nobody can sign in. |
| **Typical trigger** | The IdP signing certificate reaches its `notAfter` date, often 1–3 years after the SP was set up, so nobody remembers it exists. |
| **Lab** | `scripts/break.sh expired-signing-cert` · `scripts/fix.sh expired-signing-cert` |

## Symptom

The user signs in at Keycloak successfully (correct password, MFA, and so on). They're sent back to the SP, which then shows this error:

```
SAML login failed
IdP signing certificate expired on 2026-10-08 15:58:32 UTC; the SP has no valid IdP certificate pinned
Reason code   idp_cert_expired
Detail        subject=CN=idlab serial=87d8c2ca81cbabef5c326105d0fb0ab7 notAfter=2026-10-08 15:58:32 UTC sp_clock=2026-10-08 15:58:38 UTC
```

How customers describe it: *"SSO stopped working for everyone this morning. Nothing changed on our side."* Every user and every browser is affected, starting at one precise moment.

Real SPs word this differently, for example "certificate expired", "Invalid signature" or "The SAML response signature could not be verified". The common factor is that the failure appears **after** a successful IdP login and affects **all** users at once.

## Where to look

Run from the repository root on the lab host.

```bash
# SP: the failure and the certificate's notAfter
docker compose logs saml-sp | grep saml_login_failed
#  ... WARNING saml-sp event=saml_login_failed reason=idp_cert_expired
#      error='IdP signing certificate expired on 2026-10-08 15:58:32 UTC; ...'

# The certificate(s) the SP trusts
openssl x509 -in .state/saml-sp/idp-signing.pem -noout -subject -serial -enddate

# IdP: Keycloak noticed too, and stopped using the key
docker compose logs keycloak | grep -E 'not valid anymore|fallback'
#  WARN [org.keycloak.keys.KeyNoteUtils] Certificate chain for kid '6dxhA-...' (idlab-expiring-signing-key)
#       is not valid anymore, disabling it (certificate expired on Thu Oct 08 15:58:32 GMT 2026)

# What the IdP publishes right now (compare with the SP's pinned certificate)
curl -s --cacert certs/ca.crt https://localhost:8180/realms/idlab/protocol/saml/descriptor \
  | grep -o '<ds:X509Certificate>[^<]*' | sed 's/<ds:X509Certificate>//' \
  | while read -r c; do printf -- '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' "$(fold -w64 <<<"$c")" \
      | openssl x509 -noout -subject -enddate; done

scripts/status.sh   # expired-signing-cert  broken  SP-pinned IdP signing cert EXPIRED ...
```

In the Keycloak admin console, go to **Realm settings → Keys**. The `RS256` key with the expired certificate shows as **Passive**. If no other key was enabled, Keycloak has also created a `fallback-RS256` key.

## Diagnosis

1. **Confirm the scope.** Do all users fail, starting at one moment, on one SP? That points to trust or configuration, not to accounts.
2. **Read the date.** Compare the `notAfter` of the SP's trusted certificate with the time the incident started. If they match to the minute, you have your answer.
3. **Rule out clock skew** ([runbook 02](02-clock-skew.md)). The SP's error includes `sp_clock`, which should match real UTC. A certificate can also *appear* expired to an SP whose clock runs fast.
4. **Check what the IdP is doing now.** Keycloak 26 won't keep signing with an expired certificate. It demotes that key to passive and signs with another enabled key, generating `fallback-RS256` if none exists. So even an SP that ignored expiry dates would now fail, with a *signature* error, because the IdP's key changed under it.

**Root cause, in one sentence for the customer:** the IdP signing certificate configured in your application expired at <time>, and the application correctly rejects assertions it can no longer trust.

## Fix

Rotate the certificate on the IdP, then re-exchange it with every SP that pinned it.

1. **IdP:** add a new signing key with a certificate valid for a year or more. Make it active, then remove or disable the expired key. Delete any `fallback-RS256` key, which was never meant to be permanent. In the lab:
   ```bash
   scripts/fix.sh expired-signing-cert
   ```
   This removes the expired, retired and fallback keys, adds a new CA-signed key valid for a year, and re-pins the SP.
2. **SP:** upload the new certificate, or re-import IdP metadata. In the lab this is `scripts/pin-idp-cert.sh`. With a real SaaS app it's the SSO settings page, which is often admin-only on the customer's side.
3. **Verify:** do a fresh login in a private window, then check `scripts/status.sh`.

For most real SPs, step 2 needs the customer's admin. Send them the new certificate or the metadata URL, and stay on the call while they update it.

## Prevention

- **Monitor expiry.** Alert at 60, 30 and 7 days before any IdP signing certificate's `notAfter`. Many IdPs, Keycloak included, will happily let you import a certificate due to expire next week.
- **Rotate with overlap.** Add the new key as *passive* first and publish both certificates in metadata. Let SPs pick it up, then make it active. SPs that consume metadata from a URL roll over with no outage.
- **Prefer metadata URLs to pasted certificates** wherever the SP supports them. Keep a list of SPs that pin certificates manually, with an owner for each.
- **Don't run on a fallback key.** If `fallback-RS256` appears in a realm, treat it as an incident in its own right.

## Questions I'd ask the customer

1. When exactly did the failures start, and does it affect every user or only some?
2. Does any other application using the same IdP still work? (This separates IdP-wide problems from per-SP trust problems.)
3. Can you send the exact error, a screenshot and a timestamp, or a SAML trace from the browser (SAML-tracer)?
4. Has anyone rotated, renewed or re-imported certificates on the IdP recently?
5. How does your application get the IdP certificate: a metadata URL it refreshes, or a certificate someone pasted in at setup?
6. Who has admin access to the SSO settings in the application, and can they join a call?
7. Is there a change freeze or approval process we need to go through to update the certificate?
