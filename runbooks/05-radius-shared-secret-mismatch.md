# 05 · RADIUS shared secret mismatch

| | |
|---|---|
| **Protocol** | RADIUS (RFC 2865) over UDP 1812, between a NAS (switch, wireless controller, VPN gateway) and the RADIUS server. The directory behind the server is fine. |
| **Blast radius** | Every user who logs in through that one NAS. Other NASes using the same server, and web SSO through the IdP for the same users, keep working. That makes it look like "the Wi-Fi is broken" or "the VPN is broken" rather than an identity problem. |
| **Typical trigger** | A NAS was replaced, factory reset or restored from an old backup; someone retyped the secret on one side (a trailing space, a wrong character, a pasted secret that was truncated); the secret was rotated on the server but not on every NAS, or the other way round. |
| **Lab** | `scripts/break.sh radius-shared-secret-mismatch` · `scripts/fix.sh radius-shared-secret-mismatch` (changes the NAS's copy of the secret; the server's client entry for the NAS is not changed) |

## Symptom

The lab's NAS sends an Access-Request for `dave` and gets **no reply at all**. After its retries it gives up:

```
$ docker compose exec nas nas-auth dave
Password for dave:
nas: Access-Request for dave to radius:1812
nas: no reply from radius:1812 after 3 attempts (6s): RADIUS server not responding
```

On a real NAS this shows up as "RADIUS server timeout", "server not responding" or the server being marked dead and the NAS failing over to the next one. The user just sees the login fail, often after a pause.

The server receives every attempt and drops it, with one line per packet:

```
Wed Oct 14 08:16:03 2026 : Info: Dropping packet without response because of error: Received packet from 172.30.181.10 with invalid Message-Authenticator!  (Shared secret is incorrect.) (from client nas)
```

Logins with a correct secret look like this, for comparison:

```
nas: Access-Accept
Wed Oct 14 08:15:54 2026 : Auth: (2) Login OK: [dave] (from client nas port 0)
```

How customers describe it: *"Nobody can connect to the Wi-Fi since we swapped the controller,"* or *"VPN logins time out, but the portal login with the same account works."*

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  radius-shared-secret-mismatch  broken   nas (172.30.181.10) has a different shared secret from the server's client entry

# Server: the decisive line (one per attempt, so three per login here)
docker compose logs radius | grep -E 'Message-Authenticator|Login (OK|incorrect)|unknown client'
#  ... Dropping packet without response because of error: Received packet from 172.30.181.10
#      with invalid Message-Authenticator!  (Shared secret is incorrect.) (from client nas)

# Send a test login from the NAS (the password is prompted for, never on the command line)
docker compose exec nas nas-auth dave
```

The server names the client (`from client nas`) and its source IP. That's the first thing to check: the request reached the server and matched the right client entry, so the network path and the client definition are fine.

Three different server lines look similar but mean different things:

| Server log | Meaning |
|---|---|
| `invalid Message-Authenticator!  (Shared secret is incorrect.)` | Known client, wrong secret. **This scenario.** |
| `Ignoring request to auth address * port 1812 bound to server default from unknown client 172.30.181.20 port 37224 proto udp` | The source IP isn't in `clients.conf` at all, often because of NAT, a new NAS IP or a different source interface. Not a secret problem. |
| `Login incorrect (ldap: Bind credentials incorrect: Invalid credentials): [dave] (from client nas port 0)` | The packet was accepted and the directory rejected the password. Usually a genuinely wrong password, but see Diagnosis for the legacy case. |

### Run FreeRADIUS in debug mode

`freeradius -X` runs the server in the foreground and prints every packet and every decision. It's the standard first step for any FreeRADIUS problem. Stop the service first, because both can't hold port 1812.

```bash
docker compose stop radius
docker compose run --rm --use-aliases radius -X      # --use-aliases: the NAS still finds it as "radius"
# in a second terminal:
docker compose exec nas nas-auth dave
# back in the first: Ctrl-C, then
docker compose start radius
```

With a wrong secret, debug mode shows nothing more than the drop, because the server refuses the packet before decoding it:

```
Ready to process requests
Dropping packet without response because of error: Received packet from 172.30.181.10 with invalid Message-Authenticator!  (Shared secret is incorrect.) (from client nas)
Dropping packet without response because of error: Received packet from 172.30.181.10 with invalid Message-Authenticator!  (Shared secret is incorrect.) (from client nas)
Dropping packet without response because of error: Received packet from 172.30.181.10 with invalid Message-Authenticator!  (Shared secret is incorrect.) (from client nas)
```

With the right secret you see the whole request, then each step:

```
(0) Received Access-Request Id 178 from 172.30.181.10:41275 to 172.30.181.2:1812 length 83
(0)   Message-Authenticator = 0xc866cdf226e43d65f3b363931aa37f87
(0)   User-Name = "dave"
(0)   User-Password = <<< secret >>>
(0)   NAS-Identifier = "nas"
...
(0) ldap: Bind as user "uid=dave,ou=people,dc=idlab,dc=example" was successful
(0) Login OK: [dave] (from client nas port 0)
(0) Sent Access-Accept Id 178 from 172.30.181.2:1812 to 172.30.181.10:41275 length 38
```

FreeRADIUS 3.2 masks passwords as `<<< secret >>>` in debug output. Don't set `suppress_secrets = no` to see them on a production server, and treat any debug capture as sensitive (it still contains usernames and client addresses) before you attach it to a ticket.

To compare, the server's secret is `RADIUS_SECRET` in `.env`. Read it on your own screen only.

## Diagnosis

1. **Timeouts for everyone on one NAS, while other logins for the same users work.** The directory and the users are fine (web SSO through the IdP still works for `dave`). Look at the path between that NAS and the RADIUS server: the network, the client entry and the secret.
2. **Did the packet arrive?** If the server logs nothing at all, it's the network or a firewall (UDP 1812 is easy to forget). If it logs `unknown client`, the source IP doesn't match a client entry. If it logs `invalid Message-Authenticator! (Shared secret is incorrect.)`, the packet arrived from a known client and **the secrets differ**. That line is the giveaway.
3. **Why it is so often mistaken for a wrong password.** RADIUS doesn't send the secret. It uses it as a key:
   - The NAS hides `User-Password` by XORing it with `MD5(secret + Request Authenticator)`. A server with a different secret "decrypts" it to random bytes, with no error, and passes those to the directory. The directory says *invalid credentials*, and the server logs `Login incorrect (ldap: Bind credentials incorrect: Invalid credentials)`, exactly as it does for a mistyped password.
   - That's what happens with a NAS that doesn't send **Message-Authenticator**, against a server that doesn't require it (`require_message_authenticator = no`, common before 2024). Everything about the failure points at the user, and help desks reset passwords that were never wrong.
   - Debug mode gives it away: with the right secret, the password decodes to printable text. With the wrong one, the lab's server (relaxed to accept a legacy NAS) printed:
     ```
     (1) ldap: ERROR: Bind credentials incorrect: Invalid credentials
     (1) WARNING: Unprintable characters in the password.  Double-check the shared secret on the server and the NAS!
     (1) Login incorrect (ldap: Bind credentials incorrect: Invalid credentials): [dave] (from client nas port 0)
     ```
   - The NAS's side doesn't match a wrong password either. The server signs its Access-Reject with *its* secret, so the NAS can't verify the reply's Response Authenticator and must discard it. Depending on the NAS, that's logged as an invalid or bad authenticator, or simply as a timeout. A wrong password produces a Reject the NAS **can** verify.
4. **How Message-Authenticator settles it.** Message-Authenticator (RFC 3579) is an HMAC-MD5 over the whole packet, keyed with the shared secret. The server checks it before it looks at anything else, so a wrong secret is reported as a wrong secret, `invalid Message-Authenticator! (Shared secret is incorrect.)`, and never reaches the password check. Since the BlastRADIUS attack (CVE-2024-3596), current servers and NASes send and require it. This lab requires it on every client.
5. **If the server says the NAS didn't send it:** a request with no Message-Authenticator, to a server that requires it, is dropped too. At normal log level that drop isn't logged at all, which is why debug mode matters. Debug mode prints:
   ```
   Receive - Insecure packet from host 172.30.181.10:  Packet does not contain required Message-Authenticator attribute.  You may need to set "require_message_authenticator = no" in the configuration.
   ```
   That's an old NAS or old firmware, not a secret mismatch. Update the NAS rather than relaxing the server.
6. **Confirm without reading the secret aloud.** Have both sides compare a hash of the configured value (for example the first characters of its SHA-256), or simply set it again on both sides from the same source.

**Root cause, in one sentence for the customer:** the shared secret configured on the NAS no longer matches the secret in the RADIUS server's client entry for that NAS, so the server can't verify the NAS's requests (invalid Message-Authenticator) and drops them without replying, and every login through that NAS times out.

## Fix

Make both sides hold the same secret, from one known-good source.

1. Decide which side is right. Usually it's the server's client entry. If the secret was rotated deliberately, it's the new value from your secret store.
2. Set it on the other side. Paste rather than retype, and check for trailing spaces and characters the NAS's CLI may treat specially. In the lab, the NAS is the side that changed:
   ```bash
   scripts/fix.sh radius-shared-secret-mismatch
   ```
3. If the server's side changed, restart or reload the server after updating its client entry. FreeRADIUS 3 reads `clients.conf` at start.
4. Verify: `docker compose exec nas nas-auth dave` prints `nas: Access-Accept`, the server logs `Login OK: [dave] (from client nas port 0)`, and `scripts/status.sh` shows `healthy`.

Don't "fix" it by setting `require_message_authenticator = no`. With a wrong secret that only turns timeouts into Access-Rejects that look like bad passwords, and it re-opens the BlastRADIUS hole.

## Prevention

- **One secret per NAS, from a secret store.** Generate it randomly (long, printable ASCII, no spaces) and keep the server's client entry and the NAS config in step from the same source. Never reuse one secret for every NAS.
- **Treat a secret rotation as one change across both sides,** with a test login straight afterwards. A NAS replacement or restore is a rotation too.
- **Monitor with a real Access-Request**, not a port check. A synthetic login from each NAS (or each site) catches this before users do. UDP 1812 being "open" proves nothing.
- **Alert on `Shared secret is incorrect`** and on `unknown client` in the server's log. Both are rare in normal operation.
- **Require Message-Authenticator** from every client (`require_message_authenticator = yes`, the default in FreeRADIUS 3.2.10). Besides protecting against BlastRADIUS, it makes this failure name itself.
- Keep the NAS's RADIUS settings (server IP, ports, secret, source interface) in its configuration backups and change review, so a restore doesn't silently bring back an old secret.

## Questions I'd ask the customer

1. Which NAS (switch, wireless controller, VPN gateway) are the failing logins going through? Do logins through other NASes, or web SSO with the same accounts, still work?
2. What does the user see: a timeout, or "wrong password"? What does the NAS log say: server timeout, server marked dead, or an invalid authenticator?
3. Has that NAS been replaced, reset, upgraded or restored from a backup recently? Has anyone changed its RADIUS settings?
4. Has the RADIUS shared secret been rotated on either side? Who holds the current value, and where is it stored?
5. Does the RADIUS server's log show `Shared secret is incorrect` or `unknown client` for that NAS's IP? Can you send me those lines and the NAS IP it shows?
6. Does the NAS send Message-Authenticator in Access-Requests? Which firmware version is it running?
7. When did it start, and does that match a change window or maintenance on the NAS?
