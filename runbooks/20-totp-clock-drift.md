# 20 · One-time codes rejected: authenticator clock drift (TOTP)

| | |
|---|---|
| **Protocol** | TOTP (RFC 6238): time-based one-time codes from an authenticator app, checked by the IdP at sign-in |
| **Blast radius** | One user, or the few whose phones share the cause. Everyone else, with or without MFA, signs in normally. If the IdP's own clock drifts instead, it's every MFA user at once. |
| **Typical trigger** | Automatic date and time turned off on the phone and the clock set by hand; a phone kept offline for a long time; travel with manual time zones; a hardware token whose clock has drifted over the years; on the server side, NTP stopped on an IdP node. |
| **Lab** | `scripts/break.sh totp-clock-drift` · `scripts/fix.sh totp-clock-drift` (moves only the `authenticator` container's clock, grace's "phone", 3 minutes ahead with libfaketime; Keycloak and the host are not changed) |

## Symptom

grace signs in with her password. Keycloak accepts it and asks for her one-time code. She types the code her app shows, and Keycloak says:

```
Invalid authenticator code.
```

She tries again with the next code, and the next. Every one fails. Her password was right all along, which is why this ticket is often filed as "MFA is broken" rather than "my phone's clock is wrong".

Other IdPs word it as "The code you entered is incorrect", "Invalid verification code" or "Token is invalid". Some count each failure towards a lockout: after a few tries the user is locked out too (see [runbook 22](22-mfa-lockout.md)).

How customers describe it: *"My codes stopped working, but my colleague's work,"* or *"It works at home but not since I came back from holiday."* When the IdP's clock is the one that drifts: *"Nobody's codes work since this morning."*

## Where to look

Run from the repository root on the lab host.

```bash
scripts/status.sh
#  totp-clock-drift  broken   the authenticator app's clock is +180s vs host, +6 steps of 30 s (faketime offset +180); Keycloak looks 1 step either side

# The "phone's" clock against the host's, and Keycloak's
date -u; docker compose exec authenticator date -u; docker compose exec keycloak date -u

# Keycloak's event: a failed login for grace's user ID, at the code step
docker compose logs keycloak | grep 'type="LOGIN_ERROR"'
#  WARN  [org.keycloak.events] (executor-thread-1) type="LOGIN_ERROR", realmName="idlab", clientId="oidc-rp",
#    userId="f74543e0-...", error="invalid_user_credentials", auth_method="openid-connect",
#    selected_credential_id="63f8dc31-...", ...

# Which user and which credential: the user's credentials list the OTP one with that ID
#   Admin console: Users -> grace -> Credentials (type otp, "Lab authenticator")
```

The event names a user ID and `selected_credential_id`, not a username. Look the user up by ID (*Users*, search by ID) and compare the credential ID with the user's credentials: if it's their `otp` credential, the failure was at the code step, so the password had already been accepted. A wrong password logs the same `invalid_user_credentials` error, but against the password credential.

## Diagnosis

1. **Password accepted, every code refused, for one user.** That's the device, not the IdP or the user's account. A wrong secret (the wrong account on the phone, or a re-enrolment the phone missed) gives the same message, so check the clock first: it's the commonest cause and the quickest to rule out.
2. **How much drift breaks it.** A code belongs to a 30-second step: the number of 30-second periods since 1970 on the phone's clock. Keycloak checks the code against its own current step and, with its default look-around window of 1, one step either side.
   - Drift under 30 seconds always works: the phone is at most one step out.
   - Drift between 30 and 60 seconds works some of the time, depending on where in the step the code is typed. That's the "it works if I wait" ticket.
   - Drift of 60 seconds or more always fails: the phone is at least two steps out. The lab's phone is 180 seconds fast, six steps.
3. **Measure it.** Ask the user to compare the phone's clock with a trusted one, to the second (many phones show seconds only in settings). In the lab: `docker compose exec authenticator date -u` against `date -u`.
4. **Check the IdP's clock too.** If the IdP is the one that's out, every MFA user fails at once, and other things break with it: tokens that look expired or not yet valid to apps, SAML assertions refused (runbook 02's symptoms, from the other side). Here, `docker compose exec keycloak date -u` matches the host.
5. **Tell it apart from runbook 02.** In [runbook 02](02-clock-skew.md), the IdP logs a successful sign-in and the *app* then refuses the assertion as expired: the clock that's wrong belongs to a server, and every user of that app fails. Here, the *IdP* refuses the sign-in itself, at the code step, before any app is involved, and only the user with the wrong clock fails. Runbook 02's IdP log is clean; this one's shows `LOGIN_ERROR`.
6. **Watch for the lockout.** Each refused code is a failed login. With brute-force protection on, five of them lock the account for a while, and then even a correct code fails ([runbook 22](22-mfa-lockout.md)). Fix the clock, and unlock the user if needed.

**Root cause, in one sentence for the customer:** the clock on your phone is about 3 minutes ahead, and one-time codes depend on the time, so your app is showing codes from 3 minutes in the future, which the sign-in service won't accept.

## Fix

Correct the clock on the device. Don't widen the IdP's window to hide it.

- **Lab:** `scripts/fix.sh totp-clock-drift` resets the authenticator's libfaketime offset to `+0`. No restart is needed.
- **Phone:** turn on automatic date and time (and time zone), using the network's time. Some authenticator apps also have a "sync time" or "time correction" option; that only corrects the app, so fix the phone's clock as well.
- **Hardware token:** these can't be reset by the user. Most IdPs that support them can resynchronise a token from two consecutive codes, or the token needs replacing.
- **IdP clock:** if the IdP's clock is the one that's out, fix time sync on every IdP node (`timedatectl set-ntp true`, `chronyc tracking`), as in runbook 02.

Then sign in again with a fresh code. If the user hit the lockout while trying, unlock them as well.

## Prevention

- Tell users, in the enrolment instructions, to keep automatic date and time on. It's the first thing a help desk script should ask.
- Monitor the IdP's clock offset and alert above about 1 second (see runbook 02's Prevention).
- Keep the look-around window small: 1 step (Keycloak's default) is usual. A larger window accepts more codes at each moment, which makes guessing easier and keeps a stolen code valid for longer, and it only postpones the ticket.
- Offer a second method (recovery codes, a second authenticator or a passkey), so a user with a broken phone isn't locked out of their work.

## Questions I'd ask the customer

1. Does your password get accepted, and then the code is refused? Or does it fail before you're asked for a code?
2. Does it fail for you only, or for colleagues too? (One user: their device. Everyone: the IdP's clock or its configuration.)
3. Is automatic date and time turned on on your phone? Can you compare its clock with another clock, to the second?
4. Have you travelled, changed the time zone by hand, or had the phone off or offline for a long time?
5. Is it an app on your phone, or a hardware token? If it's a token, how old is it?
6. How many times have you tried? (Five failures may have locked the account as well.)
