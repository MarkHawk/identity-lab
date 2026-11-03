#!/usr/bin/env python3
"""The lab's authenticator app: it plays the phone of an MFA demo user.

    authenticator code <user>            the code the app shows now
    authenticator code <user> --new      wait for a code this app hasn't shown yet
    authenticator code <user> --wrong    a code that is valid at no nearby time step
    authenticator otpauth <user> [--qr]  the enrolment URI (or a QR code), to add the
                                         user to your own phone; terminal only
    authenticator selftest               the RFC 6238 test vectors (the health check)

Codes are time-based one-time passwords (TOTP, RFC 6238) from the user's
enrolled secret, which reaches this container as <USER>_TOTP_SECRET (base32,
from .env). Like most authenticator apps, it always uses HMAC-SHA1, 6 digits
and a 30-second step, whatever the enrolment asked for.

The container's clock is shifted by libfaketime (.state/authenticator/
faketime.rc), so a scenario can make the "phone's" clock wrong without
touching anything else. The container has no network: codes leave it only
through `docker compose exec`, as a person reads them off a screen.

Nothing here ever prints a secret, except `otpauth`, which refuses unless
its output is a terminal.
"""

import base64
import hashlib
import hmac
import os
import re
import struct
import subprocess
import sys
import time

ALGORITHM, DIGITS, PERIOD = "sha1", 6, 30
ISSUER = "Identity Lab"
# The time steps whose codes --new has shown, per user, so it never repeats
# one (the IdP refuses a code that has already been used).
STATE_DIR = "/tmp/authenticator"


def totp(key, t, digits=DIGITS, period=PERIOD, algorithm=ALGORITHM):
    """RFC 6238: HOTP (RFC 4226) over the number of periods since the epoch."""
    counter = int(t // period)
    mac = hmac.new(key, struct.pack(">Q", counter), algorithm).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 10 ** digits:0{digits}d}"


def secret_b32(user):
    if not re.fullmatch(r"[a-z]+", user):
        sys.exit("authenticator: user names are lower-case letters")
    value = os.environ.get(f"{user.upper()}_TOTP_SECRET", "")
    if not value:
        sys.exit(f"authenticator: no account for {user} in this app")
    return value


def key_of(user):
    b32 = secret_b32(user).upper()
    return base64.b32decode(b32 + "=" * (-len(b32) % 8))


def shown_steps_file(user):
    return os.path.join(STATE_DIR, f"{user}.shown-steps")


def shown_steps(user):
    try:
        with open(shown_steps_file(user)) as fh:
            return [int(x) for x in fh.read().split()]
    except (FileNotFoundError, ValueError):
        return []


def cmd_code(user, mode):
    key = key_of(user)
    if mode == "--wrong":
        # Not the code of any step within 5 either side of now.
        now = time.time()
        near = {totp(key, now + i * PERIOD) for i in range(-5, 6)}
        code = int(totp(key, now))
        while f"{code:0{DIGITS}d}" in near:
            code = (code + 500000 + 1) % 10 ** DIGITS
        print(f"{code:0{DIGITS}d}")
        return
    if mode == "--new":
        # Wait for a step whose code this app hasn't shown, as a person waits
        # for the app to change. A set, not just the last step: when the
        # clock is put back (scenarios/totp-clock-drift.sh), the steps it
        # showed while it was fast are still ahead.
        os.makedirs(STATE_DIR, exist_ok=True)
        shown = shown_steps(user)
        while int(time.time() // PERIOD) in shown:
            time.sleep(0.5)
    now = time.time()
    if mode == "--new":
        with open(shown_steps_file(user), "w") as fh:
            fh.write(" ".join(str(x) for x in (shown + [int(now // PERIOD)])[-50:]))
    print(totp(key, now))


def cmd_otpauth(user, qr):
    if not sys.stdout.isatty():
        sys.exit("authenticator: otpauth prints the secret, so it only writes to a terminal.\n"
                 "Run it on your own screen: scripts/authenticator.sh otpauth "
                 f"{user}{' --qr' if qr else ''}")
    from urllib.parse import quote
    label = quote(f"{ISSUER}:{user}")
    uri = (f"otpauth://totp/{label}?secret={secret_b32(user)}&issuer={quote(ISSUER)}"
           f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}")
    print(f"This is {user}'s TOTP secret. Don't share it, paste it into a ticket or chat, or\n"
          "show it in a screenshot or screen share. If it leaks: scripts/setup.sh --rotate,\n"
          "then scripts/test.sh --fresh, and add the account to your phone again.\n",
          file=sys.stderr)
    if qr:
        # The URI goes to qrencode on stdin, never on its command line.
        subprocess.run(["qrencode", "-t", "ansiutf8"], input=uri.encode(), check=True)
    else:
        print(uri)


# RFC 6238 Appendix B: the seeds and the expected 8-digit codes.
VECTORS = {
    "sha1": (b"12345678901234567890",
             ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"]),
    "sha256": (b"12345678901234567890123456789012",
               ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"]),
    "sha512": (b"1234567890123456789012345678901234567890123456789012345678901234",
               ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"]),
}
VECTOR_TIMES = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]


def cmd_selftest():
    bad = [(alg, t) for alg, (key, codes) in VECTORS.items()
           for t, want in zip(VECTOR_TIMES, codes) if totp(key, t, 8, 30, alg) != want]
    if bad:
        sys.exit(f"authenticator: RFC 6238 test vectors failed: {bad}")
    print(f"authenticator: RFC 6238 test vectors pass ({sum(len(c) for _, c in VECTORS.values())} codes)")


def main(argv):
    usage = __doc__.split("\n\n")[1]
    if argv[:1] == ["selftest"] and len(argv) == 1:
        return cmd_selftest()
    if len(argv) in (2, 3) and argv[0] == "code" and argv[2:] in ([], ["--new"], ["--wrong"]):
        return cmd_code(argv[1], argv[2] if len(argv) == 3 else "")
    if len(argv) in (2, 3) and argv[0] == "otpauth" and argv[2:] in ([], ["--qr"]):
        return cmd_otpauth(argv[1], len(argv) == 3)
    sys.exit(usage)


if __name__ == "__main__":
    main(sys.argv[1:])
