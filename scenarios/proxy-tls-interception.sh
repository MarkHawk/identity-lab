# shellcheck shell=bash disable=SC2034  # SCENARIO_* are read by the scripts that source this file
# The proxy team turns on TLS inspection ("SSL bump") on the egress proxy.
# Squid now ends the RP's TLS itself and presents a certificate for
# keycloak that it minted and signed with its own inspection CA. The OIDC
# RP trusts only the lab CA, so certificate verification fails on every
# call to Keycloak. Browsers and the direct RP (:8182) don't use the proxy
# and keep working.
SCENARIO_SUMMARY="the egress proxy re-signs TLS with an inspection CA the OIDC RP doesn't trust"
SCENARIO_RUNBOOK="runbooks/13-proxy-tls-interception.md"
SCENARIO_APP=oidc-egress
SCENARIO_UNAFFECTED="oidc alice"
SCENARIO_EXPECT="certificate verify failed: self-signed certificate in certificate chain"
SCENARIO_SEEN_AT="on the app's \"OIDC login failed\" page, after the password (or straight after \"Log in\" if the app restarted since its last login)"
SCENARIO_LOG='squid SQUID_TLS_ERR_ACCEPT\+TLS_LIB_ERR=A000418'

_pti_file=tls.conf

scenario_detect() { squid_conf_detect "$_pti_file" "the RP doesn't trust the proxy's inspection CA"; }

scenario_break() {
  squid_conf_set "$_pti_file" <<'CONF'
# The proxy's port and what it does with HTTPS. Broken by scenarios/proxy-tls-interception.sh:
# TLS inspection on. Squid ends each client's TLS, reads the request, and
# makes its own connection to the server, presenting the client a
# certificate minted for that server and signed by the inspection CA.
http_port 3128 ssl-bump tls-cert=/etc/idlab/squid-ca.crt tls-key=/etc/idlab/squid-ca.key generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
sslcrtd_program /usr/local/squid/libexec/security_file_certgen -s /tmp/ssl_db -M 4MB
sslcrtd_children 3 startup=1 idle=1
acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all
CONF
}
scenario_fix() { squid_conf_restore "$_pti_file"; }

# While broken: the certificate the RP is shown for keycloak really is the
# proxy's, not Keycloak's.
SCENARIO_ALSO="the certificate presented for keycloak is issued by the proxy's inspection CA"
scenario_also_check() {
  local out
  # shellcheck disable=SC2016  # Python, not shell
  out="$(compose exec -T oidc-rp-egress python -c '
import socket, ssl
from cryptography import x509
s = socket.create_connection(("squid", 3128), timeout=5)
s.sendall(b"CONNECT keycloak:8180 HTTP/1.1\r\nHost: keycloak:8180\r\n\r\n")
s.recv(4096)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
cert = x509.load_der_x509_certificate(ctx.wrap_socket(s, server_hostname="keycloak").getpeercert(True))
print("subject:", cert.subject.rfc4514_string()); print("issuer:", cert.issuer.rfc4514_string())' 2>&1)"
  echo "$out"
  grep -qF "issuer: CN=identity-lab Egress Inspection CA" <<<"$out"
}
