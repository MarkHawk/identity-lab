# 23 · RADIUS with MFA: the NAS doesn't handle Access-Challenge

| | |
|---|---|
| **Protocol** | RADIUS (RFC 2865) with a second factor by Access-Challenge: the server checks the password, answers Access-Challenge with a `State` and a prompt, and the NAS sends a second Access-Request with the one-time code (TOTP) and that `State` |
| **Blast radius** | Every user who needs MFA, through every NAS that can't do challenge-response. Users without MFA, and MFA users on a NAS that can, keep working. So it looks like "the VPN rejects some people" rather than an MFA problem. |
| **Typical trigger** | MFA switched on at the RADIUS server (or the user added to the MFA group) without checking every NAS; a NAS replaced by a model, firmware or profile that only does plain PAP; a management login on a switch or firewall; a VPN connection type (some L2TP/IPsec and older client setups) that can't show a second prompt. |
| **Lab** | `scripts/break.sh radius-challenge-unsupported` · `scripts/fix.sh radius-challenge-unsupported` (turns the NAS's challenge-response setting off in its volume, `/var/lib/nas/challenge`; the server is not changed) |

## Symptom

heidi is in the directory's `mfa-required` group. She types her password on the NAS and is never asked for a code. The login just fails:

```
$ docker compose exec nas nas-auth heidi
Password for heidi:
nas: Access-Request for heidi to radius:1812
nas: Access-Reject
```

A healthy NAS asks for the code instead:

```
nas: Access-Request for heidi to radius:1812
nas: Access-Challenge (Message-Authenticator verified): Enter the code from your authenticator app
Enter the code from your authenticator app:
nas: Access-Request for heidi to radius:1812, answering the challenge
nas: Access-Accept
```

dave, who isn't in the MFA group, logs in through the same NAS as usual. heidi's password is right: on a NAS that can prompt, she gets in.

On a real NAS the user sees "Authentication failed", "Login incorrect" or a VPN client's "credentials rejected", straight after the password. Nothing ever mentions a code.

How customers describe it: *"Since MFA went live, some people can't get on the VPN, and they never get asked for a code,"* or *"MFA works on the new firewall but not the old one."*

## Where to look

Run from the repository root on the lab host.

```bash
scripts/status.sh
#  radius-challenge-unsupported  broken   nas (172.30.181.10) treats Access-Challenge as Access-Reject (challenge-response off)

# The server's side: the decisive evidence
docker compose logs radius | grep -E 'Challenge sent|Login (OK|incorrect)' | grep heidi
#  Tue Nov  3 21:34:30 2026 : Auth: Challenge sent: [heidi] (from client nas port 0)
#  ... and nothing after it for that attempt: no Login OK, no Login incorrect

# The NAS's own log, if it has one this clear (see below)
docker compose logs nas | grep discarded
#  2026-11-03T21:34:30Z nas: Access-Challenge from radius:1812 for heidi discarded: challenge-response not enabled (treated as Access-Reject)
```

The server sent a challenge and then heard nothing more: no second Access-Request. That's the signature of this failure. A wrong password ends with `Login incorrect` and no challenge; a wrong code ends with `Challenge sent` and then `Login incorrect`; a NAS that can't prompt ends with `Challenge sent` and silence.

| Server log for one attempt | Meaning |
|---|---|
| `Challenge sent: [heidi]`, then `Login OK: [heidi]` | Password and code accepted. Healthy. |
| `Challenge sent: [heidi]`, then `Login incorrect: [heidi]` | The password was right, the code wasn't (or was used before). See runbook 20 for the phone's clock. |
| `Challenge sent: [heidi]`, then nothing | The NAS never answered the challenge. **This scenario.** |
| `Login incorrect: [heidi]` with no challenge before it | The password was wrong; the server never got as far as MFA. |
| `Invalid user: [heidi]`, then `Login incorrect` | A second-round request with a `State` the server didn't issue, or one that expired. |

**Don't rely on the NAS's log.** The lab's NAS logs `Access-Challenge ... discarded: challenge-response not enabled`, but many real NASes log nothing that clear: a plain "authentication failed", "RADIUS reject" for the user, or nothing at all. Some even report it as a reject *from the server*, which it isn't. The dependable evidence is the server's `Challenge sent` line, plus no second Access-Request in a capture.

### In a packet capture

Capture UDP 1812 on the server (`tcpdump -ni any -w mfa.pcap udp port 1812`) while the user tries once. A healthy MFA login is four packets:

```
NAS -> server   Access-Request    User-Name, User-Password (the password), Message-Authenticator
server -> NAS   Access-Challenge  State, Reply-Message, Message-Authenticator
NAS -> server   Access-Request    User-Name, User-Password (the code), State (copied back), Message-Authenticator
server -> NAS   Access-Accept     Message-Authenticator
```

This failure stops after the second packet: the challenge goes out, and nothing comes back from the NAS. If the NAS retries, you'll see the *first* Access-Request again, not a second one with `State`.

### Debug mode

`freeradius -X` shows the whole exchange (see runbook 05 for running it). Be careful with the capture: FreeRADIUS masks `User-Password` as `<<< secret >>>`, but **not** `TOTP-Password`, the copy of the code the TOTP module reads, and **not** `TOTP-Secret`. In the lab, debug mode prints heidi's code and her TOTP secret in clear, once each per login. Treat a debug capture as holding the user's MFA secret, don't attach it to a ticket, and rotate the secret if it leaked. Normal logging prints neither.

## Diagnosis

1. **Only MFA users fail, and only through some NASes.** dave, without MFA, gets in through the same NAS; heidi gets in through a NAS that can prompt (in the lab: with the setting on). The directory, the password and the server's MFA configuration are fine. Look at what this NAS does with an Access-Challenge.
2. **Confirm the challenge was sent and never answered.** The server's log shows `Challenge sent` and no second request; a capture shows the same. If there's no `Challenge sent`, the user isn't in the MFA group, or the password failed first.
3. **Why it's a reject, not a timeout.** RFC 2865 (section 4.4) says a NAS that doesn't support challenge-response must treat an Access-Challenge as an Access-Reject. So the user gets an immediate, ordinary failure, with nothing to suggest a second step was ever asked for.
4. **Message-Authenticator on the challenge.** The server signs the Access-Challenge with Message-Authenticator, as it does every reply, and the NAS must check it before it trusts the `State` (BlastRADIUS, CVE-2024-3596). The lab tests both failures: a challenge with its Message-Authenticator removed is discarded by `nas-auth` itself (`Access-Challenge without Message-Authenticator discarded`), and one whose Message-Authenticator doesn't verify is dropped by radclient before `nas-auth` sees it. Either way, the code is never sent. A NAS that discards challenges for this reason looks the same from the server, so check its Message-Authenticator settings and firmware too.
5. **A code is used up once accepted, at both ends.** FreeRADIUS's `rlm_totp` refuses a code it has already accepted: the lab's second login with the same code got `Login incorrect`. Keycloak does the same for web logins (`otpPolicyCodeReusable` is false by default). Each keeps its own record, though: where one authenticator is enrolled at both (the lab gives grace and heidi separate secrets), a code used on the VPN can still be used once on the web, and the other way round. And `rlm_totp` keeps its record in memory, so a server restart forgets it.
6. **Tell it apart from a timeout.** With push-approval MFA (the user taps "approve" on their phone), the server holds the first Access-Request open until the user responds. A NAS with a 3 to 5 second RADIUS timeout gives up and retries, which often sends a second push, and the user sees "server not responding". That's the related ticket this lab doesn't model: its MFA is a typed code, which the server checks in milliseconds, so the NAS's timeout never matters. The fix there is a NAS timeout of 30 to 60 seconds with fewer retries, not this runbook's.

**Root cause, in one sentence for the customer:** the RADIUS server now asks MFA users for a one-time code after their password, using an Access-Challenge, but this NAS can't show that second prompt, so it treats the request for a code as a rejection and the user is never asked.

## Fix

Either make the NAS handle the challenge, or stop sending it one.

1. **Turn challenge-response on at the NAS**, if it supports it: often a setting on the RADIUS server entry or the authentication profile ("challenge-response", "RADIUS challenge", "allow Access-Challenge", or a newer VPN connection type). Upgrade firmware if that's what adds it.
   - **Lab:** `scripts/fix.sh radius-challenge-unsupported`.
2. **If the NAS can't, append the code to the password** for that NAS only: the user types `password123456`, and the server splits off the last 6 digits and checks both in one Access-Request. This works with any NAS. It means a policy on the server for that NAS's client entry (`&Client-Shortname`), and users need to be told, since nothing prompts them.
3. **Or don't require MFA through that NAS,** if another control covers it (a management network, a jump host), and record the exception.

Verify: `docker compose exec nas nas-auth heidi` asks for the code and ends with `nas: Access-Accept`; the server logs `Challenge sent` then `Login OK: [heidi]`.

Don't fix it by taking users out of the MFA group: that removes the second factor everywhere, not just on the NAS that can't prompt.

## Prevention

- Before switching MFA on at the RADIUS server, list every NAS that uses it and test an MFA login through each one, with a test user in the MFA group.
- Roll MFA out by group, not all at once, so a NAS that can't prompt shows up with a few users, not all of them.
- Keep a record of which NASes do challenge-response and which use the appended-code policy, and include it in NAS replacement checklists.
- Alert on `Challenge sent` without a following request from the same NAS, if your logging can join them.

## Questions I'd ask the customer

1. Does it fail for everyone, or only for users who have MFA? Through which device (VPN gateway, wireless controller, switch or firewall login)?
2. Is the user ever asked for a code? Or does it fail straight after the password?
3. When was MFA switched on for RADIUS, or the user added to the MFA group? Was this NAS replaced or upgraded around then?
4. Does the same user get in through another NAS, or through the web sign-in with MFA?
5. Does the RADIUS server's log show a challenge sent for the user, and then a second request from the NAS? Can you send a capture of one attempt?
6. Does the NAS support RADIUS challenge-response (Access-Challenge)? Which model and firmware is it? Is an "append the code to the password" option possible for it?
