# 04 · LDAP bind failure (user federation)

| | |
|---|---|
| **Protocol** | LDAP simple bind over LDAPS, between the IdP and the directory. SAML and OIDC are only the messengers. |
| **Blast radius** | Every user who comes from the directory, in every app that uses the IdP. Local IdP users (often the break-glass admin) still work, which makes it look intermittent or "only some people". |
| **Typical trigger** | The directory service account's password was rotated or expired and nobody updated the IdP; the account was disabled, locked or moved to another OU; someone retyped the bind password in the IdP console. |
| **Lab** | `scripts/break.sh ldap-bind-failure` · `scripts/fix.sh ldap-bind-failure` (stores a wrong bind credential on Keycloak's `idlab-ldap` federation; the directory and its service account are not changed) |

## Symptom

The user enters their username and password at Keycloak, and gets one of two messages. Which one depends on whether that user has logged in before.

A user who **has logged in before** (already imported into Keycloak, such as `dave` in the lab) sees an error page:

```
We are sorry...
Unexpected error when handling authentication request to identity provider.
« Back to Application
```

A directory user who has **never logged in before** stays on the login form with:

```
Invalid username or password.
```

Local Keycloak users, such as `alice`, log in normally.

The LDAP result code behind both is **49, invalid credentials**: the directory rejected the IdP's own service account, not the user. Clients show it as `ldap_bind: Invalid credentials (49)` (OpenLDAP tools) or `[LDAP: error code 49 - Invalid Credentials]` (Java). Active Directory adds a sub-code, for example `80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e`.

How customers describe it: *"Nobody can log in since this morning, but the admin account works,"* or *"SSO says our passwords are wrong, and they're not."*

## Where to look

Run from the repository root on the lab host.

```bash
# One-line answer
scripts/status.sh
#  ldap-bind-failure  broken  Keycloak cannot bind as cn=keycloak-svc,ou=services,dc=idlab,dc=example: LDAP result 49, invalid credentials

# IdP: the real cause is in the "Caused by" lines of a stack trace
docker compose logs keycloak | grep -E 'error code 49|federated user validation'
#  WARN  [org.keycloak.storage.UserStorageManager] User storage provider idlab-ldap failed during federated
#        user validation: org.keycloak.storage.StorageUnavailableException: LDAP server is unavailable for provider [idlab-ldap]
#  Caused by: javax.naming.AuthenticationException: [LDAP: error code 49 - Invalid Credentials]

# IdP: the login event (misleading on its own, see Diagnosis)
docker compose logs keycloak | grep LOGIN_ERROR
#  type="LOGIN_ERROR", realmName="idlab", clientId="oidc-rp", userId="null", error="invalid_user_credentials", ...   <- user seen before
#  type="LOGIN_ERROR", realmName="idlab", clientId="https://idlab.home:8181/saml/metadata", userId="null", error="user_not_found", ...   <- never seen

# Directory: which DN tried to bind, and the result
docker compose logs ldap | grep -A1 'BIND dn="cn=keycloak-svc'
#  conn=1027 op=0 BIND dn="cn=keycloak-svc,ou=services,dc=idlab,dc=example" method=128
#  conn=1027 op=0 RESULT tag=97 err=49 qtime=0.000027 etime=0.000161 text=
```

In the admin console, go to **User federation → idlab-ldap**. Under *Connection and authentication settings*, use **Test connection** first (network and TLS), then **Test authentication** (the bind DN and stored password). `scripts/status.sh` calls the same check through the Admin API.

The apps' logs show nothing. The failure happens inside the IdP before any assertion or token is issued, so the user never returns to the app.

### Test a bind by hand with ldapwhoami

`ldapwhoami` does a bind and reports who the directory thinks you are. That makes it the cleanest test of a DN and password. The directory has no host port, so run it from a container. `-W` prompts for the password, so it never ends up in your shell history or the process list.

```bash
# From inside the directory container (tests credentials and TLS)
docker compose exec ldap ldapwhoami -x -H ldaps://ldap:1636 \
  -D cn=keycloak-svc,ou=services,dc=idlab,dc=example -W
#  Enter LDAP Password:
#  dn:cn=keycloak-svc,ou=services,dc=idlab,dc=example      <- password is right
#  ldap_bind: Invalid credentials (49)                       <- password (or DN) is wrong

# From a throwaway container on the IdP's network (also tests DNS and the network path,
# the way the IdP reaches the directory)
docker run --rm -it --network identity-lab_default \
  -v "$PWD/certs/ca.crt:/etc/idlab/ca.crt:ro" --entrypoint ldapwhoami identity-lab/ldap:local \
  -x -H ldaps://ldap:1636 -D cn=keycloak-svc,ou=services,dc=idlab,dc=example -W

# The same test for one user's own password (what the IdP does after finding the user)
docker compose exec ldap ldapwhoami -x -H ldaps://ldap:1636 \
  -D uid=dave,ou=people,dc=idlab,dc=example -W
```

To compare, the right bind password is `LDAP_BIND_PASSWORD` in `.env`. Read it on your own screen only.

## Diagnosis

1. **Local users work, directory users don't.** That points straight at user federation. The SAML and OIDC configuration, certificates and clocks are all fine, because local users go through exactly the same flows.
2. **Don't trust the first log line.** Keycloak's WARN says `LDAP server is unavailable`, but the server is up. The `Caused by: ... error code 49` lines under it give the real cause. The login event also misleads: `invalid_user_credentials` or `user_not_found`, while the user's password and account are fine.
3. **Which bind failed: the service account or the user?** The IdP binds twice per login. First it binds as its service account to find the user, then as the user to check their password.
   - The service account fails (`status.sh`, *Test authentication*, or `ldapwhoami -D cn=keycloak-svc,...` returns 49): it's this scenario, and every directory user is affected.
   - The service account works but `ldapwhoami -D uid=<user>,...` returns 49: that one user's password really is wrong, or their account is locked. It's a user problem, not an outage.
4. **Error 49 doesn't always mean "wrong password".** It also covers a mistyped bind DN, or a DN that no longer exists because the account moved OU. On Active Directory, the `data` sub-code tells you which: `52e` wrong password, `525` user not found, `530`/`531` logon hours or workstation restriction, `532` password expired, `533` account disabled, `701` account expired, `773` must change password, `775` locked out.
5. **Check what changed on the directory side.** Look at the service account's `pwdLastSet` or `pwdChangedTime`, its expiry policy, and any lockout. A lockout can come from the IdP itself retrying an old password.

**Root cause, in one sentence for the customer:** the IdP's directory service account `cn=keycloak-svc` can no longer authenticate to LDAP (result 49, invalid credentials), because the password stored in the IdP doesn't match the one in the directory. Without that account the IdP can't find any directory user, so every directory login fails, whatever password the user types.

## Fix

Make the IdP's stored bind password match the directory, using a known-good value.

1. Confirm the right password works with `ldapwhoami` (above) **before** you change the IdP.
2. Store it in the IdP. In the console: **User federation → idlab-ldap → Bind credentials**, then **Test authentication**, then **Save**. In the lab:
   ```bash
   scripts/fix.sh ldap-bind-failure
   ```
3. If the account is **locked or expired** rather than mistyped, unlock it or reset it on the directory first, then update the IdP with the new password.
4. Verify: `scripts/status.sh` shows `healthy`, and a directory user (`dave`) can log in from a new private window.

Don't "fix" it by binding as the directory administrator (`cn=admin`). That works, but it gives the IdP write access to the whole directory and puts the most powerful credential in another system.

## Prevention

- **Rotate the service account password as one change across both systems.** Update the IdP in the same change (or use a secret manager both sides read), and test immediately with *Test authentication*.
- **Know the service account's password policy.** Many directories expire service account passwords by default. Either exempt the account under an approved policy, or put the expiry date in a calendar with a named owner.
- **Monitor the bind, not just the port.** A synthetic check that binds as the service account (like `scripts/status.sh` here) or performs a directory user login (like `scripts/test.sh`) catches this before users do. A TCP or TLS check on 636 doesn't.
- **Alert on `err=49` for the service account DN** in directory logs, and on `error code 49` in IdP logs.
- **Keep a local break-glass admin** in the IdP that doesn't depend on the directory. In this scenario it's how you get in to fix things.
- Use a dedicated, read-only account per IdP, never a person's account or the directory administrator.

## Questions I'd ask the customer

1. Does it affect everyone who signs in with their directory account, or only some users? Can a local IdP admin still log in?
2. What exactly does the user see: an error page ("Unexpected error...") or "Invalid username or password" on the login form? Have the affected users logged in through SSO before?
3. Has anyone rotated, reset or changed the password of the directory service account the IdP uses? Is that account subject to password expiry?
4. Has the service account been moved, renamed, disabled or locked recently? Can your directory team check its lockout status and last password change?
5. What does **Test authentication** on the IdP's LDAP settings say right now?
6. Can you run `ldapwhoami` (or `ldp.exe` on Windows) with the bind DN and the password you believe is correct, from a host on the same network as the IdP, and send the result code?
7. When did it start, and does that match a change window, a password expiry date, or a directory migration?
