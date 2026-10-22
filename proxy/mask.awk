# Masks one-time login values in nginx's logs: their values in query strings
# become ***. nginx writes the full request line into its error log (e.g. on
# a 504 for the OIDC callback) and there is no setting to change that, so
# both logs pass through this filter (proxy/run.sh). Parameter names stay.
#   code, state, session_state      OIDC authorisation code and CSRF values
#   nonce, code_challenge           bind the ID token and the code to this login
#   SAMLRequest, SAMLResponse       SAML messages
#   Signature                       the signature on a redirect-binding message
#   session_code, client_data       Keycloak's login-actions URLs; client_data
#                                   is base64 JSON that holds the state
# A name only matches whole (code= never matches code_challenge=).
# fflush() after every line: the logs must not lag behind the requests.
BEGIN { n = split("code state session_state nonce code_challenge SAMLRequest SAMLResponse Signature session_code client_data", p, " ") }
{
  for (i = 1; i <= n; i++) {
    gsub("[?]" p[i] "=[^&[:space:]\"]+", "?" p[i] "=***")
    gsub("&" p[i] "=[^&[:space:]\"]+", "\\&" p[i] "=***")
  }
  print; fflush()
}
