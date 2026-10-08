#!/usr/bin/env bash
# Trust the lab CA in Chromium's NSS database, then run the e2e script.
set -euo pipefail
mkdir -p "$HOME/.pki/nssdb"
certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password 2>/dev/null || true
certutil -d "sql:$HOME/.pki/nssdb" -A -t "C,," -n identity-lab-ca -i /etc/idlab/ca.crt
exec python3 /tests/e2e.py "$@"
