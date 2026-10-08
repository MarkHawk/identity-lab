# 02 · Clock skew between IdP and SP (SAML)

| | |
|---|---|
| **Protocol** | SAML 2.0 (assertion `Conditions` timing) |
| **Blast radius** | Every SAML login to the affected SP host, or to some nodes behind a load balancer, which makes failures look random. |
| **Typical trigger** | NTP stopped or blocked on the SP server, a VM restored from a snapshot, a host resumed from suspend, or a container on a host with a drifting clock. |
| **Lab** | `scripts/break.sh clock-skew` · `scripts/fix.sh clock-skew` (shifts only the `saml-sp` container's clock by +10 minutes with libfaketime; the host clock is not changed) |

## Symptom

The user signs in at Keycloak successfully. Back at the SP:

```
SAML login failed
Could not validate timestamp: expired. Check system clock.
Reason code   invalid_response
Detail        errors=invalid_response sp_clock=2026-10-08 17:05:12 UTC

Assertion timing vs SP clock
IssueInstant              2026-10-08T16:55:12.745Z
Conditions NotBefore      2026-10-08T16:55:10.745Z
Conditions NotOnOrAfter   2026-10-08T16:56:10.745Z
SP clock now              2026-10-08T17:05:12Z
SP clock − IssueInstant   +600 s
```

The lab SP prints the assertion's validity window next to its own clock. A real SP usually shows only the first two lines, so you have to work out the comparison yourself (see *Where to look*).

If the SP's clock runs **slow** instead of fast, python3-saml reports the opposite:
`Could not validate timestamp: not yet valid. Check system clock.`

Other SP stacks word it as "Assertion is expired", "NotOnOrAfter condition not met", "Response is not yet valid" or `SAML2 assertion ... is outside of the allowed clock skew`.

How customers describe it: *"SSO fails for everyone, but the IdP says the logins succeeded."* Sometimes: *"It works on and off,"* when only one node behind a load balancer has a bad clock.

## Where to look

Run from the repository root on the lab host.

```bash
# SP log. Note the line's timestamp: the app formats it using its own (wrong) clock.
docker compose logs --timestamps saml-sp | grep saml_login_failed
#  saml-sp-1  | 2026-10-08T16:55:12.805Z 2026-10-08 17:05:12,804 WARNING saml-sp event=saml_login_failed
#    reason=invalid_response error='Could not validate timestamp: expired. Check system clock.'
#    detail='errors=invalid_response sp_clock=2026-10-08 17:05:12 UTC' sp_clock_minus_issue_instant='+600 s'
#               ^ Docker's receive time (real)  ^ the SP's own clock: 10 minutes ahead

# Compare clocks directly
date -u; docker compose exec saml-sp date -u

# The IdP side is clean: no LOGIN_ERROR for the SAML client (prints nothing)
docker compose logs keycloak --since 10m | grep LOGIN_ERROR | grep 'saml/metadata'

scripts/status.sh   # clock-skew  broken  saml-sp clock is +600s vs host (faketime offset +600)
```

The SP shows `IssueInstant`, `NotBefore` and `NotOnOrAfter` next to "SP clock now", along with `SP clock − IssueInstant`. It does this on the error page when a login fails and on `/debug` when one succeeds. That's the quickest visual check: a healthy lab shows a few seconds at most.

## Diagnosis

1. **The IdP says success and the SP says the timestamps are invalid.** That combination almost always means clocks. The SAML message itself is fine.
2. **Measure the offset.** Compare `date -u` on the SP host with a trusted source: the IdP host, `chronyc tracking`, or `timedatectl`. In the lab, the SP is 600 seconds ahead.
3. **Do the arithmetic.** Keycloak issues assertions valid for about 60 seconds (`NotOnOrAfter` = `IssueInstant` + 60s). python3-saml allows 300 seconds of drift (`ALLOWED_CLOCK_DRIFT = 300`). An SP more than about 6 minutes fast sees every assertion as expired, and one more than about 5 minutes slow sees them as not yet valid. Skew below that passes, which is why small drift goes unnoticed until it crosses the line.
4. **Check every node.** If failures are intermittent, check the clock on each SP instance behind the load balancer, not just the one you SSH'd into.
5. **Tell it apart from runbook 01.** An expired certificate produces a certificate error, with a `notAfter` date in the detail. Skew produces a timestamp error. Both can be triggered by a fast SP clock, so check the clock first.

**Root cause, in one sentence for the customer:** your application server's clock is about 10 minutes ahead of real time, so it treats every freshly issued SAML assertion as already expired.

## Fix

Correct the clock on the SP host. Don't widen the tolerance to hide it.

- **Lab:** `scripts/fix.sh clock-skew` resets the libfaketime offset to `+0`. No restart is needed.
- **Real server:** re-enable time sync, for example `timedatectl set-ntp true`, or `systemctl restart chronyd` then `chronyc makestep`. Then confirm with `chronyc tracking` (or `timedatectl show-timesync`). Make sure outbound UDP 123 is allowed, or point the host at an internal NTP server.
- **VMs and containers:** containers share the host kernel's clock, so fix the **host**. For VMs, check that hypervisor time sync isn't fighting NTP.

Verify with a fresh login in a private window. The `/debug` page's "SP clock now" should match real UTC.

## Prevention

- Monitor clock offset on every host (for example, the node exporter's `node_timex_offset_seconds`, or `chronyc tracking` checks), and alert above about 1 second.
- Include the time-sync service in hardening baselines and golden images. Re-check it after restoring snapshots.
- Keep SP clock tolerance small, ideally 1–3 minutes. A large tolerance weakens replay protection and only postpones the outage.
- Log both the SP's view of time and the assertion's validity window on failure, as this lab's SP does, so the first log line answers the question.

## Questions I'd ask the customer

1. Does the IdP show these sign-ins as successful? (If yes, the problem is on the SP side.)
2. Can you run `date -u` on the application server(s) right now and paste the output alongside the real time?
3. Is the application behind a load balancer? Does it fail on every attempt or only some?
4. Was the server recently restored from a snapshot, migrated, resumed or rebuilt?
5. Which NTP or time-sync service does the server use, and can it reach its time source (firewall, proxy)?
6. Did the problem start gradually (drift) or suddenly (a time jump)?
