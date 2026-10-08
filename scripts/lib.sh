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
  local v
  for v in LAB_HOST KC_PORT SAML_SP_PORT OIDC_RP_PORT KC_ADMIN_USER KC_ADMIN_PASSWORD; do
    [[ -n "${!v:-}" ]] || die "$v is missing from .env -- re-run scripts/setup.sh"
  done
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

# --- Keycloak Admin REST API ---------------------------------------------------
# Calls go to https://$LAB_HOST:$KC_PORT pinned to 127.0.0.1 (so LAN DNS is not
# needed) and verify TLS against the lab CA. The admin password is passed on
# stdin, never on a command line.
_KC_TOKEN="" _KC_TOKEN_AT=0

# LAB_HOST, KC_PORT etc. come from .env via load_env.
# shellcheck disable=SC2153
kc_curl() {
  curl -sS --fail-with-body --cacert "$CERTS_DIR/ca.crt" \
    --resolve "$LAB_HOST:$KC_PORT:127.0.0.1" "$@"
}

kc_token() {
  if [[ -z "$_KC_TOKEN" ]] || (( $(date +%s) - _KC_TOKEN_AT > 40 )); then
    _KC_TOKEN="$(printf '%s' "$KC_ADMIN_PASSWORD" | kc_curl \
      "https://$LAB_HOST:$KC_PORT/realms/master/protocol/openid-connect/token" \
      -d grant_type=password -d client_id=admin-cli \
      --data-urlencode "username=$KC_ADMIN_USER" --data-urlencode "password@-" \
      | jq -r .access_token)" || die "could not get a Keycloak admin token (is the lab up?)"
    _KC_TOKEN_AT="$(date +%s)"
  fi
}

# kc_api <METHOD> <path under /admin/realms> [json-body]
kc_api() {
  local method="$1" path="$2" body="${3:-}"
  kc_token
  local args=(-X "$method" -H "Authorization: Bearer $_KC_TOKEN")
  [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" --data-binary @-)
  printf '%s' "$body" | kc_curl "${args[@]}" "https://$LAB_HOST:$KC_PORT/admin/realms$path"
}

REALM=idlab

# --- Scenarios -------------------------------------------------------------------
# Each scenarios/<name>.sh defines:
#   SCENARIO_SUMMARY   one line for status output
#   SCENARIO_RUNBOOK   path of the runbook
#   SCENARIO_APP       saml|oidc  -- which app's login shows the failure
#   SCENARIO_EXPECT    text the user sees when it is broken (asserted by test.sh)
#   SCENARIO_SEEN_AT   where that text appears, for break.sh's instructions
#   SCENARIO_LOG       "<service> <grep -E pattern>" -- log evidence (asserted by test.sh)
#   scenario_detect    print "broken|healthy|unknown<TAB>detail", from live lab state
#   scenario_break / scenario_fix
SCENARIOS_DIR="$LAB_ROOT/scenarios"

scenario_names() {
  local f
  for f in "$SCENARIOS_DIR"/*.sh; do basename "$f" .sh; done
}

load_scenario() {
  local name="$1"
  [[ "$name" =~ ^[a-z0-9-]+$ && -f "$SCENARIOS_DIR/$name.sh" ]] \
    || die "unknown scenario '$name' (available: $(scenario_names | tr '\n' ' '))"
  unset -f scenario_detect scenario_break scenario_fix
  # shellcheck disable=SC1090
  source "$SCENARIOS_DIR/$name.sh"
}

scenario_state() { scenario_detect | cut -f1; }

app_url()   { case "$1" in saml) echo "https://$LAB_HOST:$SAML_SP_PORT/" ;; oidc) echo "https://$LAB_HOST:$OIDC_RP_PORT/" ;; esac; }
app_title() { case "$1" in saml) echo "SAML" ;; oidc) echo "OIDC" ;; esac; }

# How to see the current scenario's failure (after break.sh).
print_try_it() {
  local t; t="$(app_title "$SCENARIO_APP")"
  cat <<TXT

    Try it:
      1. Open a NEW private/incognito window. An existing app or Keycloak
         session in a normal window can hide the error.
      2. Go to $(app_url "$SCENARIO_APP") and click "Log in with $t" (sign in as alice if asked).
      3. Expect, $SCENARIO_SEEN_AT:
           $SCENARIO_EXPECT
    Runbook: $SCENARIO_RUNBOOK
    Undo:    scripts/fix.sh $1
TXT
}

# How to confirm recovery (after fix.sh).
print_confirm() {
  local t; t="$(app_title "$SCENARIO_APP")"
  cat <<TXT

    Confirm recovery: in a NEW private window, go to $(app_url "$SCENARIO_APP"),
    click "Log in with $t" and sign in as alice. You should land on the
    "$t login succeeded" page. scripts/status.sh should show $1 as healthy.
TXT
}

# --- SAML SP trust -----------------------------------------------------------------
IDP_PIN_FILE="$STATE_DIR/saml-sp/idp-signing.pem"

# Signing certificates in the realm's SAML metadata, one base64 DER per line.
idp_metadata_certs() {
  kc_curl "https://$LAB_HOST:$KC_PORT/realms/$REALM/protocol/saml/descriptor" \
    | grep -o '<ds:X509Certificate>[^<]*' | sed 's/<ds:X509Certificate>//'
}

b64_to_pem() { printf -- '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' "$(fold -w64 <<<"$1")"; }

# Base64 DER bodies of the certificates pinned on the SP, one per line.
pinned_certs() {
  [[ -f "$IDP_PIN_FILE" ]] || return 0
  awk '/-----BEGIN CERTIFICATE-----/{c="";next} /-----END CERTIFICATE-----/{print c;next} {c=c $0}' "$IDP_PIN_FILE"
}

# Pin the currently valid signing certificates from the IdP metadata on the SP,
# the way an admin pastes the IdP certificate into a SaaS app at onboarding.
pin_idp_cert() {
  local tmp c n=0
  tmp="$(mktemp "$STATE_DIR/saml-sp/.pin.XXXXXX")"
  while read -r c; do
    [[ -n "$c" ]] || continue
    if b64_to_pem "$c" | openssl x509 -noout -checkend 0 >/dev/null; then
      b64_to_pem "$c" >>"$tmp"; n=$((n + 1))
    fi
  done < <(idp_metadata_certs)
  (( n > 0 )) || { rm -f "$tmp"; die "IdP metadata has no valid signing certificate to pin"; }
  chmod 644 "$tmp"
  mv "$tmp" "$IDP_PIN_FILE"
  echo "$n"
}
