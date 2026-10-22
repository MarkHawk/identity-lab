#!/usr/bin/env bash
# Generate the lab's local CA, TLS and signing certificates, and random
# secrets in .env. Safe to re-run: existing secrets are kept, certificates
# are only reissued when missing, near expiry, or LAB_HOST has changed.
#
#   scripts/setup.sh                      # first run, LAB_HOST=idlab.home
#   LAB_HOST=localhost scripts/setup.sh   # e.g. in CI
#   scripts/setup.sh --rotate             # new random value for every secret in .env
#                                         # (then: scripts/test.sh --fresh)
#   scripts/setup.sh --force              # regenerate CA, keys and secrets (then: scripts/test.sh --fresh)
#
# Nothing secret is ever printed. Read values from .env when you need them.
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
require openssl docker date base64

FORCE=0 ROTATE=0
case "${1:-}" in
  "")       ;;
  --force)  FORCE=1 ;;
  --rotate) ROTATE=1 ;;
  *) die "unknown option: $1 (use --rotate or --force)" ;;
esac

rand() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c "${1:-32}"; }

# Value from an existing .env, without sourcing it.
existing() { [[ -f "$ENV_FILE" ]] && sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1 || true; }

if (( FORCE )); then
  warn "--force: regenerating CA, certificates and all secrets"
  warn "existing Keycloak data will not match; run 'scripts/test.sh --fresh' afterwards"
  rm -rf "$CERTS_DIR" "$ENV_FILE"
fi

LAB_HOST="${LAB_HOST:-$(existing LAB_HOST)}"
LAB_HOST="${LAB_HOST:-idlab.home}"
[[ "$LAB_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || die "LAB_HOST must be a DNS name, got: $LAB_HOST"

mkdir -p "$CERTS_DIR" "$STATE_DIR/saml-sp"
chmod 700 "$CERTS_DIR"

# --- Local CA ---------------------------------------------------------------
if [[ ! -f "$CERTS_DIR/ca.key" || ! -f "$CERTS_DIR/ca.crt" ]]; then
  log "creating local CA"
  ( umask 077
    openssl req -x509 -new -newkey rsa:3072 -nodes -sha256 -days 3650 \
      -keyout "$CERTS_DIR/ca.key" -out "$CERTS_DIR/ca.crt" \
      -subj "/O=identity-lab/CN=identity-lab Local CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null )
  chmod 644 "$CERTS_DIR/ca.crt"
  rm -f "$CERTS_DIR/tls.crt" "$CERTS_DIR/sp-signing.crt" "$CERTS_DIR/ldap.crt"   # force reissue under the new CA
fi

# --- TLS certificate shared by the services and the proxy -------------------
# DNS:proxy: oidc-rp-proxied reaches Keycloak through https://proxy:8183.
# DNS:api: the OIDC RP calls the API (resource server) at https://api:8188.
SAN="DNS:$LAB_HOST,DNS:keycloak,DNS:saml-sp,DNS:oidc-rp,DNS:proxy,DNS:api,IP:127.0.0.1"
[[ "$LAB_HOST" != "localhost" ]] && SAN="$SAN,DNS:localhost"
needs_tls=0
if [[ ! -f "$CERTS_DIR/tls.crt" ]]; then
  needs_tls=1
elif ! openssl x509 -in "$CERTS_DIR/tls.crt" -noout -checkend $((30*86400)) >/dev/null; then
  needs_tls=1
elif ! openssl x509 -in "$CERTS_DIR/tls.crt" -noout -ext subjectAltName 2>/dev/null \
       | grep -q "DNS:$LAB_HOST\b"; then
  needs_tls=1
elif ! openssl x509 -in "$CERTS_DIR/tls.crt" -noout -ext subjectAltName 2>/dev/null \
       | grep -q "DNS:proxy\b"; then
  needs_tls=1   # issued before the reverse proxy existed
elif ! openssl x509 -in "$CERTS_DIR/tls.crt" -noout -ext subjectAltName 2>/dev/null \
       | grep -q "DNS:api\b"; then
  needs_tls=1   # issued before the API existed
fi
if (( needs_tls )); then
  log "issuing TLS certificate for $LAB_HOST"
  issue_cert "$CERTS_DIR/tls" "$LAB_HOST" "-1 hour" "+397 days" server "$SAN"
fi

# --- SAML SP signing certificate ---------------------------------------------
if [[ ! -f "$CERTS_DIR/sp-signing.crt" ]] \
   || ! openssl x509 -in "$CERTS_DIR/sp-signing.crt" -noout -checkend $((30*86400)) >/dev/null; then
  log "issuing SAML SP signing certificate"
  issue_cert "$CERTS_DIR/sp-signing" "saml-sp signing" "-1 hour" "+2 years" signing
fi

# --- LDAP server certificate (LDAPS on the compose network only) -------------
# Separate from tls.crt: the directory is never reached as LAB_HOST.
if [[ ! -f "$CERTS_DIR/ldap.crt" ]] \
   || ! openssl x509 -in "$CERTS_DIR/ldap.crt" -noout -checkend $((30*86400)) >/dev/null; then
  log "issuing LDAP server certificate"
  issue_cert "$CERTS_DIR/ldap" ldap "-1 hour" "+397 days" server "DNS:ldap"
fi

# --- Egress proxy interception CA ----------------------------------------------
# Squid re-signs intercepted TLS with this CA in the proxy-tls-interception
# scenario. It is deliberately separate from the lab CA, and nothing trusts it.
if [[ ! -f "$CERTS_DIR/squid-ca.key" || ! -f "$CERTS_DIR/squid-ca.crt" ]]; then
  log "creating the egress proxy's interception CA"
  ( umask 077
    openssl req -x509 -new -newkey rsa:2048 -nodes -sha256 -days 3650 \
      -keyout "$CERTS_DIR/squid-ca.key" -out "$CERTS_DIR/squid-ca.crt" \
      -subj "/O=identity-lab egress proxy/CN=identity-lab Egress Inspection CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null )
  chmod 644 "$CERTS_DIR/squid-ca.crt"
fi

# --- mTLS client certificate --------------------------------------------------
# The certificate a partner system presents to the proxy's mutual-TLS route
# (:8189). certs/ holds the healthy copy; the client uses the one in
# .state/mtls-client/, which the client-cert-* scenarios remove or replace.
if [[ ! -f "$CERTS_DIR/mtls-client.crt" ]] \
   || ! openssl x509 -in "$CERTS_DIR/mtls-client.crt" -noout -checkend $((30*86400)) >/dev/null; then
  log "issuing the mTLS client certificate"
  issue_cert "$CERTS_DIR/mtls-client" "partner-client" "-1 hour" "+397 days" client
fi

# Containers run as the invoking user (LAB_UID), so keys can stay 0600.
chmod 600 "$CERTS_DIR"/*.key

# --- Scenario state -----------------------------------------------------------
# libfaketime offset read by the SAML SP (see scenarios/clock-skew.sh).
[[ -f "$STATE_DIR/saml-sp/faketime.rc" ]] || echo "+0" >"$STATE_DIR/saml-sp/faketime.rc"
# Extra seconds the OIDC RP behind the proxy takes to answer its callback
# (see scenarios/proxy-gateway-timeout.sh).
mkdir -p "$STATE_DIR/oidc-rp-proxied"
[[ -f "$STATE_DIR/oidc-rp-proxied/callback-delay" ]] || echo "0" >"$STATE_DIR/oidc-rp-proxied/callback-delay"
# The reverse proxy's scenario-owned settings, healthy defaults from proxy/defaults/.
mkdir -p "$STATE_DIR/proxy"
for f in "$LAB_ROOT"/proxy/defaults/*.conf; do
  [[ -f "$STATE_DIR/proxy/${f##*/}" ]] || install -m 644 "$f" "$STATE_DIR/proxy/${f##*/}"
done

# The egress proxy's scenario-owned settings (squid/defaults/*.conf), and the
# proxy settings of the OIDC RP behind it (see scenarios/proxy-bypass.sh).
mkdir -p "$STATE_DIR/squid" "$STATE_DIR/oidc-rp-egress"
for f in "$LAB_ROOT"/squid/defaults/*.conf; do
  [[ -f "$STATE_DIR/squid/${f##*/}" ]] || install -m 644 "$f" "$STATE_DIR/squid/${f##*/}"
done
[[ -f "$STATE_DIR/oidc-rp-egress/proxy.env" ]] \
  || install -m 644 "$LAB_ROOT/squid/defaults/oidc-rp-egress.env" "$STATE_DIR/oidc-rp-egress/proxy.env"

# The mTLS client's certificate, copied once. Not re-copied when present (or
# deliberately removed by scenarios/client-cert-missing.sh): fix.sh does that.
if [[ ! -d "$STATE_DIR/mtls-client" ]]; then
  mkdir -p "$STATE_DIR/mtls-client"
  install -m 644 "$CERTS_DIR/mtls-client.crt" "$STATE_DIR/mtls-client/client.crt"
  install -m 600 "$CERTS_DIR/mtls-client.key" "$STATE_DIR/mtls-client/client.key"
fi

# The origin the API allows in its CORS responses: the direct OIDC RP's,
# whose debug page calls it from the browser (see scenarios/cors-blocked.sh).
mkdir -p "$STATE_DIR/api"
[[ -f "$STATE_DIR/api/cors-allow-origin" ]] || echo "https://$LAB_HOST:8182" >"$STATE_DIR/api/cors-allow-origin"

# --- .env ---------------------------------------------------------------------
# Keep an existing secret, unless rotating.
keep() {
  local v=""
  (( ROTATE )) || v="$(existing "$1")"
  printf '%s' "${v:-$2}"
}

if (( ROTATE )); then
  log "writing .env with NEW values for every secret (certificates unchanged)"
else
  log "writing .env (existing secrets are kept)"
fi
tmp_env="$(mktemp "$LAB_ROOT/.env.XXXXXX")"
chmod 600 "$tmp_env"
cat >"$tmp_env" <<ENV
# Generated by scripts/setup.sh -- contains secrets, never commit.
# Re-running setup.sh keeps these values; --rotate regenerates them.

LAB_HOST=$LAB_HOST
LAB_UID=$(id -u)

KC_PORT=8180
SAML_SP_PORT=8181
OIDC_RP_PORT=8182
# The same three, through the nginx reverse proxy.
PROXY_KC_PORT=8183
PROXY_SAML_SP_PORT=8184
PROXY_OIDC_RP_PORT=8185
# The OIDC RP whose calls to Keycloak go through the Squid egress proxy.
EGRESS_OIDC_RP_PORT=8186
# A fourth OIDC RP, through the reverse proxy, which talks plain HTTP to it.
PROXY_EDGE_RP_PORT=8187
# The API (resource server) that accepts Keycloak access tokens.
API_PORT=8188
# The reverse proxy's route that requires a client certificate (mutual TLS).
PROXY_MTLS_PORT=8189

KC_ADMIN_USER=admin
KC_ADMIN_PASSWORD=$(keep KC_ADMIN_PASSWORD "$(rand 32)")
POSTGRES_PASSWORD=$(keep POSTGRES_PASSWORD "$(rand 32)")
DEMO_PASSWORD=$(keep DEMO_PASSWORD "$(rand 20)")
OIDC_CLIENT_SECRET=$(keep OIDC_CLIENT_SECRET "$(rand 40)")
# Client secret of oidc-rp-proxied, the OIDC RP behind the proxy.
OIDC_PROXIED_CLIENT_SECRET=$(keep OIDC_PROXIED_CLIENT_SECRET "$(rand 40)")
# Client secret of oidc-rp-egress, the OIDC RP behind the egress proxy.
OIDC_EGRESS_CLIENT_SECRET=$(keep OIDC_EGRESS_CLIENT_SECRET "$(rand 40)")
# Client secret of oidc-rp-edge, the OIDC RP behind the proxy on plain HTTP.
OIDC_EDGE_CLIENT_SECRET=$(keep OIDC_EDGE_CLIENT_SECRET "$(rand 40)")
SAML_SP_SECRET_KEY=$(keep SAML_SP_SECRET_KEY "$(rand 48)")
OIDC_RP_SECRET_KEY=$(keep OIDC_RP_SECRET_KEY "$(rand 48)")
LDAP_ADMIN_PASSWORD=$(keep LDAP_ADMIN_PASSWORD "$(rand 32)")
LDAP_BIND_PASSWORD=$(keep LDAP_BIND_PASSWORD "$(rand 32)")
RADIUS_LDAP_BIND_PASSWORD=$(keep RADIUS_LDAP_BIND_PASSWORD "$(rand 32)")
# Shared secret between the FreeRADIUS server and the lab's NAS (the client).
RADIUS_SECRET=$(keep RADIUS_SECRET "$(rand 32)")
# Password of egress-svc, the account Squid asks for when proxy login is on
# (scenarios/proxy-auth-required.sh). Hashed inside the Squid container.
EGRESS_PROXY_PASSWORD=$(keep EGRESS_PROXY_PASSWORD "$(rand 32)")

# Public certificate (not secret): Keycloak uses it to verify signed AuthnRequests.
SP_SIGNING_CERT=$(cert_b64 "$CERTS_DIR/sp-signing.crt")
ENV
mv "$tmp_env" "$ENV_FILE"

if (( ROTATE )); then
  ok "rotated KC_ADMIN_PASSWORD POSTGRES_PASSWORD DEMO_PASSWORD OIDC_CLIENT_SECRET OIDC_PROXIED_CLIENT_SECRET OIDC_EGRESS_CLIENT_SECRET OIDC_EDGE_CLIENT_SECRET SAML_SP_SECRET_KEY OIDC_RP_SECRET_KEY LDAP_ADMIN_PASSWORD LDAP_BIND_PASSWORD RADIUS_LDAP_BIND_PASSWORD RADIUS_SECRET EGRESS_PROXY_PASSWORD"
  warn "the running lab still uses the OLD secrets: the Postgres password, Keycloak admin,"
  warn "demo user passwords, OIDC client secrets and LDAP passwords are only applied when the"
  warn "databases are created, and the RADIUS secret when the NAS volume is created."
  warn "Recreate the lab now:  scripts/test.sh --fresh   (deletes the Keycloak, LDAP and NAS volumes)"
  exit 0
fi
ok "setup complete for https://$LAB_HOST:8180 (Keycloak), :8181 (SAML SP), :8182 (OIDC RP)"
echo "    Through the reverse proxy: :8183 (Keycloak), :8184 (SAML SP), :8185 (OIDC RP)."
echo "    The OIDC RP behind the egress proxy (Squid): :8186."
echo "    The OIDC RP behind the reverse proxy on plain HTTP: :8187. The API (resource server): :8188."
echo "    Through the reverse proxy, with a client certificate (mutual TLS): :8189."
echo "    All URLs are https://. Browsers will warn about the lab's own CA; clicking through"
echo "    is fine for a lab. Don't install certs/ca.crt as a trusted root (see README)."
echo "    Demo users alice, bob, carol (Keycloak) and dave, erin, frank (LDAP) share DEMO_PASSWORD in .env."
