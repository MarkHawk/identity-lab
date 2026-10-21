# Masks one-time login values in nginx's logs: the values of code, state,
# session_state, SAMLRequest and SAMLResponse in query strings become ***.
# nginx writes the full request line into its error log (e.g. on a 504 for
# the OIDC callback) and there is no setting to change that, so both logs
# pass through this filter (proxy/run.sh). Parameter names stay, and
# look-alikes such as code_challenge and session_code are left alone.
# fflush() after every line: the logs must not lag behind the requests.
BEGIN { n = split("code state session_state SAMLRequest SAMLResponse", p, " ") }
{
  for (i = 1; i <= n; i++) {
    gsub("[?]" p[i] "=[^&[:space:]\"]+", "?" p[i] "=***")
    gsub("&" p[i] "=[^&[:space:]\"]+", "\\&" p[i] "=***")
  }
  print; fflush()
}
