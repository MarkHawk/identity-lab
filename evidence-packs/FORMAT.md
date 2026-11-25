# Evidence packs

What a support engineer would see from each tool while one of the lab's failures is happening, captured from the real lab, redacted, and written as JSON for the support-training game (and later triage-assistant's demo mode). The game shows a tool's output when the player taps it.

```
evidence-packs/
  FORMAT.md                this file
  packs/healthy.json       the lab with nothing broken, for comparison
  packs/case-<id>.json     one per scenario
  answers/case-<id>.json   what each case is: read separately, never shown with the pack
```

Build them all with:

```bash
scripts/evidence-packs.sh             # healthy, then every scenario: break, capture, fix
scripts/evidence-packs.sh <name>...   # only these (healthy, or scenario names)
```

The lab ends healthy. Raw captures stay in a 0700 folder outside the repository and are deleted when the script ends.

## Ids and answers

A case's id is `case-` and six random hexadecimal digits, made once and kept: the builder reads the existing answer keys and reuses each scenario's id, so rebuilding changes the content, not the names. Nothing in a pack names its scenario, runbook, fix or summary, and `scripts/test.sh` checks that.

An answer key:

```json
{
  "id": "case-2b199b",
  "scenario": "cookie-dropped",
  "runbook": "runbooks/24-cookie-dropped.md",
  "summary": "the SAML SP's session cookie is SameSite=None without Secure: browsers refuse it",
  "fix": {"command": "scripts/fix.sh cookie-dropped", "first_step": "Give the cookie a combination browsers accept. In the lab:"}
}
```

`summary` is the scenario's `SCENARIO_SUMMARY`; `fix.first_step` is the first step of the runbook's *Fix* section.

## A pack

```json
{
  "format": "idlab-evidence-pack/1",
  "id": "case-2b199b",
  "login_at": "2026-06-14T02:14:00Z",
  "captured": "2026-06-14T02:14:04Z",
  "lab": {"host": "lab.example"},
  "tools": [
    {
      "tool": "logs-saml-sp",
      "title": "SAML app log",
      "command": "docker compose logs --since 2026-06-14T02:13:47Z --until 2026-06-14T02:14:04Z saml-sp",
      "lines": [
        {"text": "2026-06-14T02:14:01.798Z ... event=saml_session_missing path=/debug session_cookie=absent", "severity": "error"}
      ],
      "omitted": 0
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `format` | `idlab-evidence-pack/1`. A change that would break a reader gets a new number. |
| `id` | The file's name without `.json`: `healthy` or `case-<id>`. |
| `login_at` | When the failing login started. Always `2026-06-14T02:14:00Z`: see [Time](#time). |
| `captured` | When the capture's window ended, on the same clock. |
| `tools` | Every tool below, always all of them, always in this order. A tool with nothing to show says so in its one line, as the real tool would; leaving it out would hint at the answer. |
| `tools[].command` | What the tool runs, as a support engineer would type it, without a secret. |
| `tools[].lines` | The output, at most 30 lines for a log, 60 for the token inspector and 40 for any other tool. |
| `tools[].lines[].severity` | `normal`, `warning` or `error`: a hint for the game's colouring, from fixed rules (below), never chosen by hand. |
| `tools[].omitted` | How many lines the cap left out. |

### The tools

| `tool` | Title | What it shows |
|---|---|---|
| `user-report` | What the user saw | The page's title and visible text (the debug page stops before its token dumps), or the network device's output for a RADIUS login |
| `compose-ps` | Container status | `docker compose ps`: service, state, status |
| `logs-keycloak`, `logs-ldap`, `logs-radius`, `logs-proxy`, `logs-squid`, `logs-saml-sp`, `logs-saml-sp-proxied`, `logs-oidc-rp`, `logs-oidc-rp-proxied`, `logs-oidc-rp-egress`, `logs-oidc-rp-edge`, `logs-api` | each service's log | From just before the break to just after the failing login, each line with Docker's timestamp, then the service's own |
| `keycloak-events` | Keycloak events | The `org.keycloak.events` lines of Keycloak's log: successful events (at info) and errors |
| `radius-test` | RADIUS test (radclient) | `nas-auth` from the NAS, which sends one Access-Request with `radclient`, the password on stdin, for the RADIUS user in the case (dave otherwise; heidi with a fresh code from her authenticator) |
| `clock` | Clock check | The host's `timedatectl` (its time zone shown as `Etc/UTC`), then each relevant container's `date -u` against the host's, with the offset |
| `token` | Token inspector | The decoded header and claims of the ID and access tokens the app got, or a summary of the SAML response (issuer, status, conditions, audience, subject, attributes) and its signing certificate. Never a token, signature, raw response, `nonce` or token hash. A login that got no token says so |
| `trusted-keys` | Trusted keys and certificates | The SAML app's pinned IdP certificate, the IdP metadata's signing certificates, the OIDC JWKS key ids, and the partner system's client certificate (or that it has none): subject, issuer, dates, fingerprint, never a key |
| `ldap-user` | LDAP lookup | `ldapsearch` for the directory user in the case (dave otherwise), with named attributes only (never `userPassword`), and the groups that list them |
| `recent-changes` | Recent changes | A change record: every setting that differs between snapshots taken before and after the break (lab state files, Keycloak's realm settings, clients, components, keys and users, the NAS), comments left out, and the realm's admin events in the window. A secret that changed is described, never shown |
| `browser-har` | Browser network log (HAR summary) | Each request of the redacted HAR (static files left out): method, URL with one-time values masked, status, redirect, and each `Set-Cookie`'s attributes with the value redacted |
| `browser-cookies` | Browser cookies | The cookie jar after each step, names and attributes only; cookies set but missing from the jar; cookies the browser said it refused, and why |
| `browser-console` | Browser console | The console's messages |

A flow with no browser (RADIUS) gives the browser tools one line, `No browser in this flow`, and a flow with no token (RADIUS, the partner system, or a login that failed before one was issued) gives the token inspector one line, `No token in this flow`: the same words in every pack, so the wording never hints at which kind of flow it was.

### Severity rules

Applied to each line after redaction (`tests/packs.py`, `severity()`), in this order:

1. A changed setting in the change record: `warning`. A console message: `error:` is an error, `warning:` a warning.
2. An HTTP request line (an access log's `"GET /x HTTP/1.1" 200`, the HAR summary's `GET https://... -> 302`, Squid's `TCP_TUNNEL/200 ... CONNECT`): **by its status code only**, 500 or more an error, 400 to 499 a warning, anything else normal. Its URL and path are never read for words: `GET /?session=expired -> 200` is normal.
3. Any other line, with its URLs and paths taken out first:
   - `error`: `ERROR`, `FATAL`, `error=`, a `*_ERROR` event, failed, refused, denied, invalid, expired, missing, absent, blocked, mismatch, `Access-Reject`, `not responding`, `Login incorrect`, a non-zero LDAP `err=`, a clock offset of 100 s or more
   - `warning`: `WARN`, warning, timed out, timeout, retry, a clock offset from 60 s to 99 s
   - `normal`: everything else

### What is left out of the logs

**The lab's own state detection never runs inside a pack's window.** `scripts/break.sh` checks a scenario's state before and after breaking it, and each scenario's check probes different things (status requests with the user agent `idlab-status`, `curl` requests to a proxy or the API, LDAP connection tests, ...), which could hint at the answer. So the builder calls the scenario's break directly, takes its "after" snapshot with read-only Admin API calls (by user IDs looked up beforehand, so Keycloak doesn't query LDAP), and checks the scenario is broken only once the window has closed. `scripts/test.sh` checks that no pack holds a recognisable probe (`idlab-status` or a `curl` user agent). Background the lab makes anyway, such as Keycloak's directory sync, stays.

Also left out: health checks (`/healthz`, `/nginx-healthz`, `Python-urllib`, slapd's own `WHOAMI` and loopback connections), `scripts/status.sh`'s probes (user agent `idlab-status`) and other `curl` probes, Keycloak's static resources, its session purge, and the `master` realm's events (the lab's own admin API logins). When a log has more lines than its cap, every warning and error is kept first, then the latest other lines, in their original order.

## Redaction

Every line goes through, in order:

1. **Secrets.** Every value from `.env` becomes `<redacted>`; JWTs, PEM blocks and SAML messages are removed; one-time URL values (`code`, `state`, `SAMLRequest`, `session_code`, ...) are masked with `tests/evidence.py`'s `mask_url`, as in the HAR. Cookie values the browser held during the build are checked for too.
2. **Placeholders**, the same in every pack:
   - `LAB_HOST` becomes `lab.example`, also inside URL-encoded values.
   - Each container's address becomes a fixed address in `192.0.2.0/24`, one for each service and network, in the compose file's order; each network's gateway (the host, as that network sees it) one in `198.51.100.0/24`; any other address `203.0.113.N`.
   - Container IDs and names become service names; the repository's path `/srv/identity-lab`; the host's name `lab-host`; a home folder `/home/user`.
   - Keycloak's user, client, component and realm IDs become `<user:alice>`, `<client:oidc-rp>`, `<component:idlab-ldap>`, `<realm:idlab>`; any other ID (sessions, codes, `jti`, `sid`, entry UUIDs, SAML request IDs) `<id-N>`, the same value getting the same N within a pack, so "the same session as before" still shows.
3. **Time** (below).

Then the build refuses to write a pack that still holds a secret, a cookie value, a token, a PEM block or one of the capture's own dates. `scripts/test.sh` scans every committed pack and answer key again with the lab's leak patterns, and also for a private address, a home folder, and the host user's or host's name, matched as whole words.

## Time

Each pack's times all move by one amount, chosen so that its failing login starts at `2026-06-14T02:14:00Z`. Every format the lab's tools print moves by exactly that amount: ISO 8601 (with `T` or a space, with fractions or Keycloak's `,ms`), nginx and Apache access log time, `ctime` (FreeRADIUS), openssl's dates, LDAP's generalised time, slapd's hexadecimal epoch, and epoch seconds and milliseconds (token claims, Squid, Keycloak's admin API). A weekday next to a date is recomputed. A date with no time moves by whole days.

So every relationship stays as it was observed: a container's clock offset from the host, how long before the login a certificate expired, a token's lifetime. Statements relative to the login ("expired, 86400 s (1.0 d) before the login", "offset +600 s") are computed from the raw times before the shift, and `scripts/test.sh` recomputes them from the shifted times for the clock and certificate scenarios and the healthy pack, and checks they agree.
