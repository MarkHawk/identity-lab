# shellcheck shell=bash
# Shared helpers for identity-lab scripts. Source this file; don't execute it.

set -euo pipefail

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS_DIR="$LAB_ROOT/certs"
STATE_DIR="$LAB_ROOT/.state"
ENV_FILE="$LAB_ROOT/.env"

if [[ -t 1 ]]; then
  C_RED=$'\e[31m' C_GRN=$'\e[32m' C_YLW=$'\e[33m' C_BLU=$'\e[34m' C_OFF=$'\e[0m'
else
  C_RED="" C_GRN="" C_YLW="" C_BLU="" C_OFF=""
fi

log()  { printf '%s==>%s %s\n' "$C_BLU" "$C_OFF" "$*"; }
ok()   { printf '%s ok %s %s\n' "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '%swarn%s %s\n' "$C_YLW" "$C_OFF" "$*" >&2; }
die()  { printf '%sfail%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; exit 1; }

require() {
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
  done
}

# Load .env into the environment without echoing anything.
load_env() {
  [[ -f "$ENV_FILE" ]] || die ".env not found -- run scripts/setup.sh first"
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
}

compose() { docker compose --project-directory "$LAB_ROOT" "$@"; }

# Issue a certificate signed by the lab CA.
#   issue_cert <out-prefix> <common-name> <not-before> <not-after> <server|signing> [san]
# Dates are anything GNU `date -d` understands ("now", "-30 days", ...).
# Uses `openssl ca` so certificates can be backdated (needed for the
# expired-signing-cert scenario) on OpenSSL 3.0 as well as newer versions.
issue_cert() {
  local out="$1" cn="$2" nb="$3" na="$4" profile="$5" san="${6:-}"
  local tmp start end
  tmp="$(mktemp -d)"
  start="$(date -u -d "$nb" +%Y%m%d%H%M%SZ)"
  end="$(date -u -d "$na" +%Y%m%d%H%M%SZ)"
  touch "$tmp/index.txt"
  openssl rand -hex 16 >"$tmp/serial"
  cat >"$tmp/ca.cnf" <<CNF
[ ca ]
default_ca = lab
[ lab ]
database        = $tmp/index.txt
new_certs_dir   = $tmp
serial          = $tmp/serial
default_md      = sha256
policy          = any
unique_subject  = no
copy_extensions = none
[ any ]
commonName = supplied
[ server ]
basicConstraints = critical,CA:FALSE
keyUsage         = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = ${san:-DNS:$cn}
[ signing ]
basicConstraints = critical,CA:FALSE
keyUsage         = critical,digitalSignature
CNF
  ( umask 077; openssl req -new -newkey rsa:2048 -nodes -keyout "$out.key" \
      -out "$tmp/req.csr" -subj "/O=identity-lab/CN=$cn" 2>/dev/null )
  openssl ca -batch -notext -config "$tmp/ca.cnf" \
    -cert "$CERTS_DIR/ca.crt" -keyfile "$CERTS_DIR/ca.key" \
    -in "$tmp/req.csr" -out "$out.crt" \
    -startdate "$start" -enddate "$end" -extensions "$profile" 2>/dev/null \
    || { rm -rf "$tmp"; die "openssl ca failed issuing $cn"; }
  chmod 644 "$out.crt"
  rm -rf "$tmp"
}

# PEM certificate body as a single base64 line (the format SAML metadata uses).
cert_b64() { openssl x509 -in "$1" -outform DER | base64 -w0; }
