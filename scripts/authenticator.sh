#!/usr/bin/env bash
# The MFA users' authenticator app (their "phone"), from the lab host.
#   scripts/authenticator.sh code grace           the code grace's app shows now
#   scripts/authenticator.sh otpauth grace [--qr] add grace to your own phone;
#                                                 prints her secret, on your screen only
# It runs `authenticator` in the authenticator container (apps/authenticator).
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
require docker
[[ $# -ge 1 ]] || die "usage: scripts/authenticator.sh code <user> | otpauth <user> [--qr]"
# A terminal is passed through, so otpauth can check it is writing to one.
if [[ -t 0 && -t 1 ]]; then
  compose exec authenticator authenticator "$@"
else
  compose exec -T authenticator authenticator "$@"
fi
