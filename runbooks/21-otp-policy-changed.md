# 21 · New starters can't enrol after an OTP policy change (TOTP)

| | |
|---|---|
| **Protocol** | TOTP (RFC 6238) enrolment: the IdP shows a secret as a QR code (an `otpauth://` URI with `algorithm`, `digits` and `period`), and the user proves the app works by typing a code |
| **Blast radius** | Only users enrolling an authenticator after the change, and only those whose app ignores the new values. Everyone already enrolled keeps working, which is why the change looks safe for days. |
| **Typical trigger** | An admin "hardens" the realm's OTP policy: HmacSHA256 or HmacSHA512 instead of HmacSHA1, 8 digits instead of 6, or a 60-second period. A security baseline or audit finding asks for it; nobody tests enrolment with the apps users actually have. |
| **Lab** | `scripts/break.sh otp-policy-changed` · `scripts/fix.sh otp-policy-changed` (sets the realm's OTP policy to HmacSHA256 and 8 digits through the Admin REST API, as the console's *Policies → OTP Policy* tab does; nothing else changes) |

## Symptom

ivan, a new starter, signs in for the first time. Keycloak accepts his password and shows **Mobile Authenticator Setup**. He scans the QR code, types the code his app shows, and gets:

```
Invalid authenticator code.
```

He tries again with the next code. Same answer. He can't finish the setup, so he can't sign in at all.

Meanwhile grace, enrolled weeks ago, signs in as usual with her 6-digit codes. So does everyone else who already had an authenticator.

Other IdPs say "The code is incorrect", "Verification failed" or "Unable to verify the authenticator". Some let the user skip the setup once, and the ticket arrives the next day.

How customers describe it: *"New joiners can't set up MFA,"* *"It works for everyone except the people who started this week,"* or *"The QR code doesn't work with my phone."*

## Where to look

Run from the repository root on the lab host.

```bash
scripts/status.sh
#  otp-policy-changed  broken   realm OTP policy: HmacSHA256, 8 digits, 30 s; new enrolments must match it, existing ones keep their own

# The realm's policy (Admin console: Authentication -> Policies -> OTP Policy)
bash -c 'source scripts/lib.sh; load_env; kc_api GET /idlab | jq "{otpPolicyType, otpPolicyAlgorithm, otpPolicyDigits, otpPolicyPeriod, otpPolicyLookAheadWindow}"'

# What an existing enrolment holds: its own algorithm, digits and period
bash -c 'source scripts/lib.sh; load_env; kc_api GET "/idlab/users/$(kc_user_id grace)/credentials" | jq -r ".[] | select(.type == \"otp\") | .credentialData"'
#  {"subType":"totp","digits":6,"counter":0,"period":30,"algorithm":"HmacSHA1","secretEncoding":"BASE32"}

# Who changed the realm, and when (admin events are on in this realm, without details)
bash -c 'source scripts/lib.sh; load_env; kc_api GET "/idlab/admin-events?operationTypes=UPDATE&resourceTypes=REALM&max=5"' \
  | jq -r '.[] | "\(.time / 1000 | todate) \(.operationType) \(.resourceType) by \(.authDetails.userId) from \(.authDetails.ipAddress)"'

# Keycloak's log: nothing. It raises no event for a refused setup code.
docker compose logs keycloak --since 10m | grep -E 'type="[A-Z_]+_ERROR"'    # prints nothing
```

On the setup page itself, **Unable to scan?** shows the key as text and the values the IdP expects: `Algorithm: SHA256`, `Digits: 8`, `Interval: 30`. That's the quickest check with the user on a call.

## Diagnosis

1. **Only new enrolments fail.** Existing users signing in fine while new starters can't set up rules out the IdP's clock, the users' passwords and the network. Look at what changed in how enrolments are made: the OTP policy.
2. **Why existing users keep working.** Keycloak stores the algorithm, digits and period with each enrolment, and checks a user's codes against their own enrolment, not the current policy. Only the look-around window and the code-reuse setting come from the policy at sign-in time. So a policy change only affects authenticators set up after it. (Some IdPs apply the new policy to every enrolment instead, and then everyone fails at once. Check which kind you're dealing with before you tell the customer who's affected.)
3. **Why the new starter fails.** The QR code now says `algorithm=SHA256&digits=8`. Many authenticator apps ignore those two parameters and always make HMAC-SHA1, 6-digit codes. Some read the period and nothing else. So the app shows a perfectly good SHA1 code for the right secret, and the IdP, expecting 8 SHA256 digits, refuses it. Apps that do honour the parameters work, so some new starters succeed and some don't, depending on their phone.
4. **The IdP's log won't help.** Keycloak 26.7 records an event only when a setup succeeds (`UPDATE_CREDENTIAL`). A refused code is shown on the page and logged nowhere, so a log search for the user finds only their successful password. The evidence is the policy, the admin event that changed it, and the setup page's manual mode.
5. **Tell it apart from runbook 20.** In [runbook 20](20-totp-clock-drift.md), an enrolled user's codes fail at sign-in, and Keycloak logs `LOGIN_ERROR`. Here it's the setup page, for new users only, with no event. A phone with a wrong clock can also fail enrolment, so if only one new starter is affected, check their clock too.

**Root cause, in one sentence for the customer:** the sign-in service was changed to ask new authenticators for 8-digit SHA256 codes, but most authenticator apps only make 6-digit SHA1 codes, so new users' apps show codes the service can't accept; people who set up MFA before the change aren't affected.

## Fix

Put the policy back to what authenticator apps actually support, then let the affected users enrol again.

1. Restore the policy: HmacSHA1, 6 digits, 30 seconds (the RFC 6238 defaults, and what nearly every app supports).
   - **Lab:** `scripts/fix.sh otp-policy-changed`.
   - **Console:** *Authentication → Policies → OTP Policy*.
2. Ask the affected users to start the setup again. The page shows a new QR code with the restored values. If one gave up halfway and is stuck, an admin can remove their half-made authenticator (*Users → the user → Credentials*) and set the *Configure OTP* required action again.
3. Verify with a real enrolment from the kind of app your users have: `scripts/test.sh` does this as ivan.

Don't re-enrol existing users "to apply the new policy" unless you've tested the stronger settings with every app you support. That turns a few new-starter tickets into a ticket from everyone.

If the stronger settings are a real requirement, roll them out properly: publish a list of supported apps that honour them, and test enrolment with each before you change the policy.

## Prevention

- Treat the OTP policy as an interface with users' devices, not a server setting. Test any change with a real enrolment on the apps your users have.
- Prefer longer secrets and rate limits over unusual algorithms. HMAC-SHA1 in TOTP is not affected by SHA-1's collision weaknesses, and 6 digits with brute-force protection is the norm.
- Turn on admin events, so the next "what changed?" has an answer with a time and an admin's name.
- Add a synthetic enrolment to your monitoring, or at least to your change checklist.

## Questions I'd ask the customer

1. Is it only people setting up MFA for the first time, or also people who already had it?
2. When did the first new starter fail? Was the OTP or MFA policy changed around then?
3. Which authenticator app is the user using? Does someone with a different app succeed?
4. On the setup page, under "Unable to scan?", what algorithm, number of digits and interval does it show?
5. Does a user who already had MFA still get 6-digit codes that work?
6. Are admin events turned on in the IdP? Can you see who changed the realm or its policies, and when?
