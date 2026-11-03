# 22 · Locked out after wrong one-time codes (brute-force protection)

| | |
|---|---|
| **Protocol** | IdP brute-force protection (account lockout) at sign-in, here triggered at the one-time code (TOTP) step |
| **Blast radius** | One account, for the lockout's length (5 minutes in the lab, at most 15). Every app that signs in through the IdP, since the lock is on the account, not on an app. |
| **Typical trigger** | A user typing codes from a phone with a wrong clock (runbook 20) or from the wrong account in their app; old codes typed after a delay; a script or device retrying a saved, stale code; someone who has the user's password guessing codes. |
| **Lab** | `scripts/break.sh mfa-lockout` · `scripts/fix.sh mfa-lockout` (five wrong codes for grace through Keycloak's login forms, 3 seconds apart; fix is the admin's *Unlock*, through the Admin REST API) |

## Symptom

grace typed a wrong code five times. Now she has the right code ready, but she doesn't get as far as typing it. Keycloak refuses her **password**:

```
Invalid username or password.
```

Her password is correct. Keycloak shows exactly this message for a locked account, on purpose: an attacker trying passwords or codes can't tell a locked account from a wrong guess. If the lock comes into force while the user is at the code step, Keycloak's message there is `Invalid authenticator code.`, again the same as a wrong code.

So the user's story is *"my password stopped working after MFA failed"*, and the obvious next step, a password reset, is the wrong one. After 5 minutes it starts working again by itself, which makes the ticket hard to reproduce.

How customers describe it: *"I can't log in any more, it says my password is wrong but it isn't,"* or *"It worked again after lunch."*

## Where to look

Run from the repository root on the lab host.

```bash
scripts/status.sh
#  mfa-lockout  broken   grace is temporarily locked out (max failures: 5 failed logins, failureFactor 5)

# The lockout record (Admin console: Users -> grace: a "temporarily locked" banner and an Unlock switch)
bash -c 'source scripts/lib.sh; load_env; bf_status grace' | jq '{numFailures, numSecondaryAuthFailures, disabled, failedLoginNotBefore, lastFailure, numTemporaryLockouts}'
#  { "numFailures": 5, "numSecondaryAuthFailures": 5, "disabled": true, "failedLoginNotBefore": 1793738962, ... }

# Keycloak's events: the five wrong codes, then the refusals while locked
docker compose logs keycloak | grep 'type="LOGIN_ERROR"' | grep -oE 'error="[a-z_]+"' | sort | uniq -c
#  after the five wrong codes and one attempt while locked:
#        5 error="invalid_user_credentials"
#        1 error="user_temporarily_disabled"
```

The two kinds of event look like this (IDs shortened):

```
type="LOGIN_ERROR", clientId="oidc-rp", userId="f745...", error="invalid_user_credentials", ..., selected_credential_id="63f8..."
type="LOGIN_ERROR", clientId="oidc-rp", userId="f745...", error="user_temporarily_disabled", ..., username="grace"
```

| Event | Meaning |
|---|---|
| `error="invalid_user_credentials"` with `selected_credential_id` (the user's OTP credential) | A wrong code. Each one counts towards the lockout. |
| `error="invalid_user_credentials"` without it | A wrong password. Counts too. |
| `error="user_temporarily_disabled"` | The account is locked. The user may well have typed everything correctly. |

`numSecondaryAuthFailures` counts the failures at the code step, so it tells you whether the lockout came from codes (5 of 5 here) or from passwords.

## Diagnosis

1. **The user says the password is wrong, and it isn't.** Look up the account's lockout record before anything else. `disabled: true` with `failedLoginNotBefore` in the future means locked, and the password message is a disguise.
2. **Which rule locked it.** Keycloak has two, and the record tells them apart:
   - **Max failures.** `numFailures` reached the realm's `failureFactor` (5 here) within `maxDeltaTimeSeconds` (12 hours). The lock lasts `waitIncrementSeconds` (300 s here), growing with further lockouts up to `maxFailureWaitSeconds` (900 s). This scenario, and scripts/status.sh says so: `max failures: 5 failed logins, failureFactor 5`.
   - **Quick login.** Two failures less than `quickLoginCheckMilliSeconds` (1 s) apart lock the account for `minimumQuickLoginWaitSeconds` (60 s), however few failures there have been. The record shows a `numFailures` below `failureFactor` with `disabled: true`. In the lab, two wrong codes sent 183 ms apart locked grace after only 2 failures, with `failedLoginNotBefore` about 60 s after the last one. scripts/status.sh reports `quick login: 2 failed login(s), ...`. That pattern means something automated (a script, a device retrying, an attacker), because people don't type that fast.
3. **Where did the failures come from?** Look at the `LOGIN_ERROR` events before the lockout: their times, `ipAddress`, `clientId` and whether they were at the code step (`selected_credential_id` is the OTP credential, `numSecondaryAuthFailures` rises). Codes from the user's own address a few seconds apart point at a broken phone ([runbook 20](20-totp-clock-drift.md)) or the wrong account in the app. Failures from an address the user doesn't recognise, with the code step reached, mean **someone else has the password**: that's a security incident, not a lockout ticket.
4. **Tell it apart from a wrong password, and from runbook 20.** A wrong password gives `invalid_user_credentials` with no `selected_credential_id`, and the record isn't locked. Runbook 20 gives `invalid_user_credentials` at the code step, with the password accepted. Only a lockout gives `user_temporarily_disabled`.

**Root cause, in one sentence for the customer:** after five wrong one-time codes, the sign-in service locked your account for 5 minutes to protect it from guessing, and while it's locked it rejects even the right password; your password itself is fine.

## Fix

Unlock the account, then fix whatever produced the wrong codes.

1. **Unlock.**
   - **Lab:** `scripts/fix.sh mfa-lockout`, the same as the admin console's *Unlock* switch on the user (or `DELETE /admin/realms/idlab/attack-detection/brute-force/users/<id>`).
   - Or wait: a temporary lock lifts by itself at `failedLoginNotBefore`.
2. **Find the cause of the wrong codes** before the user tries again, or they'll be locked again in five tries. The phone's clock ([runbook 20](20-totp-clock-drift.md)), the wrong account in the app, or a stale enrolment ([runbook 21](21-otp-policy-changed.md)).
3. **If the failures weren't the user's,** treat the password as compromised: reset it, end the user's sessions, and look at where the attempts came from. Don't just unlock.

Don't reset the password for a locked account unless it's compromised: the password was never the problem, and the reset teaches the user that the error meant what it said. Unlock the account instead.

Don't turn brute-force protection off, or raise `failureFactor` a long way, to stop the tickets. With the password known, the code is all that's left between an attacker and the account, and six digits is only a million guesses.

## Prevention

- Teach the help desk that "my password is wrong" right after MFA trouble usually means a lockout, and to check the lockout record first.
- Keep lockouts temporary and short (minutes, growing with repeats), rather than permanent: permanent lockout turns a phone with a wrong clock into an outage for that user, and lets anyone lock any account they know the name of.
- Alert on `user_temporarily_disabled` from addresses the user has never used, and on quick-login lockouts: both suggest automation.
- Give users a clear, separate path when their authenticator is broken (recovery codes, a second method), so they don't burn through their attempts.

## Questions I'd ask the customer

1. What exactly does the message say, and at which step: after the password, or after the code?
2. Before this started, did the codes fail? How many times did you try?
3. Is your phone's date and time set automatically? (See runbook 20.)
4. Did it start working again on its own after a few minutes?
5. Were you the one trying to sign in? If not, or if you're not sure, when did you last use your password and where?
6. Does anything else sign in with your account automatically, such as a script or a mail client, that could be retrying an old code?
