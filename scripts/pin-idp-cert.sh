#!/usr/bin/env bash
# Pin the IdP's current SAML signing certificate(s) on the SAML SP.
#
# The SP does not refresh IdP metadata: like most SaaS service providers it
# trusts the certificate an admin configured at onboarding. Run this once
# after the lab first comes up, and again after the IdP rotates its key.
source "$(dirname "$0")/lib.sh"
require curl jq openssl
load_env
mkdir -p "$STATE_DIR/saml-sp"
n="$(pin_idp_cert)"
ok "pinned $n IdP signing certificate(s) on the SAML SP"
while read -r c; do
  b64_to_pem "$c" | openssl x509 -noout -subject -enddate | paste -sd' ' | sed 's/^/    /'
done < <(pinned_certs)
