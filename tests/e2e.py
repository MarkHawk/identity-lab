"""Scripted browser logins against the identity-lab sample apps.

    e2e.py saml --expect ok
    e2e.py oidc --expect-error "Invalid parameter: redirect_uri"
    e2e.py oidc-proxy --expect ok

saml-proxy and oidc-proxy are the copies of the apps behind the nginx
reverse proxy; their whole login, Keycloak included, goes through it.
oidc-egress is the OIDC RP whose own calls to Keycloak go through the Squid
egress proxy; the browser reaches it and Keycloak directly. oidc-edge is the
OIDC RP behind the reverse proxy on plain HTTP. oidc-api logs in to the
direct OIDC RP, then has it call the API with the access token (Call the
API); oidc-api-late waits API_LATE_SECONDS after logging in before it calls,
longer than a shortened access token lifespan (scenarios/api-bearer-expired.sh)
and far shorter than the normal one, so it passes on a healthy lab.
oidc-token logs in to the direct OIDC RP and fetches /debug/access-token,
the raw token, as a request in the same browser session rather than a page
visit, so the evidence saved for the run never holds it; scripts/test.sh
then checks that no token reached any log or evidence file.
oidc-cors logs in to the direct OIDC RP, then has its debug page call the
API from the browser (Call the API from the browser), a cross-origin fetch;
the browser console's messages are part of what it checks, since a CORS
refusal is only explained there.
mtls opens the reverse proxy's mutual-TLS route, presenting the client
certificate in /etc/idlab/mtls-client/ if there is one (the partner
system's, from .state/mtls-client/), and none if there isn't.

Each run uses a fresh browser context (no Keycloak SSO session carried
over), signs in as a demo user (E2E_USER, default alice; LDAP users such as
dave work the same way), and checks where the flow ends up. Exit
status 0 means the expectation held. A screenshot and the final page HTML
are written to /results on every run.
"""

import argparse
import os
import re
import sys
import time

from playwright.sync_api import Error as PWError
from playwright.sync_api import TimeoutError as PWTimeout
from playwright.sync_api import sync_playwright

LAB_HOST = os.environ["LAB_HOST"]


def url(port_var):
    return f"https://{LAB_HOST}:{os.environ[port_var]}"


# target: (app base URL, the Keycloak address that app sends the browser to)
APPS = {
    "saml": (url("SAML_SP_PORT"), url("KC_PORT")),
    "oidc": (url("OIDC_RP_PORT"), url("KC_PORT")),
    "saml-proxy": (url("PROXY_SAML_SP_PORT"), url("PROXY_KC_PORT")),
    "oidc-proxy": (url("PROXY_OIDC_RP_PORT"), url("PROXY_KC_PORT")),
    "oidc-egress": (url("EGRESS_OIDC_RP_PORT"), url("KC_PORT")),
    "oidc-edge": (url("PROXY_EDGE_RP_PORT"), url("PROXY_KC_PORT")),
    "oidc-api": (url("OIDC_RP_PORT"), url("KC_PORT")),
    "oidc-api-late": (url("OIDC_RP_PORT"), url("KC_PORT")),
    "oidc-token": (url("OIDC_RP_PORT"), url("KC_PORT")),
    "oidc-cors": (url("OIDC_RP_PORT"), url("KC_PORT")),
    "mtls": (url("PROXY_MTLS_PORT"), None),
}
API_LATE_SECONDS = 15
USER = os.environ.get("E2E_USER", "alice")
PASSWORD = os.environ["DEMO_PASSWORD"]
EXPECTED_EMAIL = f"{USER}@idlab.example"
RESULTS = os.environ.get("RESULTS_DIR", "/results")
MTLS_CLIENT_DIR = "/etc/idlab/mtls-client"
# What the mutual-TLS route answers when it accepts the client certificate.
MTLS_OK = '"client_certificate":"accepted"'


def client_certificates(app):
    """The partner system's certificate for the mutual-TLS route, if it has one.

    Playwright presents it through its own TLS proxy, which runs in Node:
    NODE_EXTRA_CA_CERTS (compose.yaml) makes it trust the lab CA.
    """
    crt, key = f"{MTLS_CLIENT_DIR}/client.crt", f"{MTLS_CLIENT_DIR}/client.key"
    if app != "mtls" or not os.path.exists(crt):
        return []
    return [{"origin": APPS["mtls"][0], "certPath": crt, "keyPath": key}]


def run(app, expect_error=None):
    args = ["--disable-dev-shm-usage"]
    if LAB_HOST != "localhost":
        # Resolve LAB_HOST to this machine without relying on LAN DNS.
        args.append(f"--host-resolver-rules=MAP {LAB_HOST} 127.0.0.1")
    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=args)
        page = browser.new_context(client_certificates=client_certificates(app)).new_page()
        try:
            outcome = flow(page, app)
        finally:
            stamp = f"{app}-{int(time.time())}"
            os.makedirs(RESULTS, exist_ok=True)
            try:
                page.screenshot(path=f"{RESULTS}/{stamp}.png", full_page=True)
                with open(f"{RESULTS}/{stamp}.html", "w") as fh:
                    fh.write(page.content())
            except Exception:  # noqa: BLE001 - evidence capture is best effort
                pass
            browser.close()

    where, text = outcome
    print(f"[{app}] ended at {where}")
    if expect_error is None:
        marker = MTLS_OK if app == "mtls" else EXPECTED_EMAIL
        if f"{app}:login-ok" == where and marker in text:
            print(f"[{app}] PASS {'client certificate accepted' if app == 'mtls' else 'login succeeded for ' + EXPECTED_EMAIL}")
            return 0
        print(f"[{app}] FAIL expected a successful login; page says:\n{excerpt(text)}")
        return 1
    if where != f"{app}:login-ok" and expect_error in text:
        print(f"[{app}] PASS saw expected error: {expect_error!r}")
        return 0
    print(f"[{app}] FAIL expected error {expect_error!r}; page says:\n{excerpt(text)}")
    return 1


def flow(page, app):
    """Drive the login and report (where-we-ended-up, visible text)."""
    base, kc = APPS[app]
    if app == "mtls":
        return mtls(page, app, base)
    try:
        page.goto(base + "/", wait_until="load")
    except PWTimeout:
        raise
    except PWError as exc:
        # The browser gave up before showing any page, e.g.
        # net::ERR_TOO_MANY_REDIRECTS from a redirect loop.
        return f"{app}:error", str(exc)
    # An error page in front of the app (e.g. a 502 from the reverse proxy).
    if page.locator("#login").count() == 0:
        return f"{app}:error", page.inner_text("body")
    page.click("#login")
    # Either Keycloak's login form, a Keycloak error page (e.g. a bad
    # redirect_uri is rejected before any form is shown), or the app's own
    # error page when it can't start the login (e.g. it couldn't fetch
    # Keycloak's discovery document through the egress proxy).
    deadline = time.monotonic() + 15
    while not page.url.startswith(kc + "/"):
        if page.url.startswith(base + "/") and app_error_shown(page):
            return f"{app}:error", page.inner_text("body")
        if time.monotonic() > deadline:
            raise PWTimeout(f"no Keycloak page after Log in; still at {page.url}")
        page.wait_for_timeout(250)
    page.wait_for_load_state("load")
    if page.locator("#username").count() == 0:
        return "keycloak:error", page.inner_text("body")
    page.fill("#username", USER)
    page.fill("#password", PASSWORD)
    page.click("#kc-login")
    try:
        page.wait_for_url(re.compile("^" + re.escape(base)), timeout=20000)
        page.wait_for_load_state("load")
    except PWTimeout:
        return f"stuck:{page.url}", page.inner_text("body")
    if not page.locator("#login-ok").count():
        return f"{app}:error", page.inner_text("body")
    if app.startswith("oidc-api"):
        return call_api(page, app)
    if app == "oidc-token":
        return fetch_token(page, app, base)
    if app == "oidc-cors":
        return call_api_from_browser(page, app)
    return f"{app}:login-ok", page.inner_text("body")


def mtls(page, app, base):
    """No login: the TLS handshake and nginx's answer are the whole flow."""
    resp = page.goto(base + "/", wait_until="load")
    text = page.inner_text("body")
    print(f"[{app}] HTTP {resp.status} with {'a' if client_certificates(app) else 'no'} client certificate")
    if resp.status == 200 and MTLS_OK in text:
        return f"{app}:login-ok", text
    return f"{app}:error", f"HTTP {resp.status}\n{text}"


def fetch_token(page, app, base):
    """Fetch the raw access token with the session's cookies; never print it."""
    # fetch() in the page: the browser's own TLS trust and cookies, and the
    # page itself stays on the debug page. (Playwright's request context
    # doesn't trust the lab CA, and its errors print the request's cookies.)
    resp = page.evaluate(
        """async (url) => {
            const r = await fetch(url, {credentials: "same-origin"});
            return {status: r.status, cacheControl: r.headers.get("cache-control"), body: await r.text()};
        }""",
        base + "/debug/access-token",
    )
    token = resp["body"].strip()
    is_jwt = re.fullmatch(r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+", token) is not None
    no_store = resp["cacheControl"] == "no-store"
    del token, resp["body"]
    print(f"[{app}] /debug/access-token: HTTP {resp['status']}, a JWT: {is_jwt}, Cache-Control no-store: {no_store}")
    if resp["status"] == 200 and is_jwt and no_store:
        return f"{app}:login-ok", page.inner_text("body")
    return f"{app}:token-error", f"HTTP {resp['status']}"


def call_api(page, app):
    """After the login: have the RP call the API with its access token."""
    if app == "oidc-api-late":
        page.wait_for_timeout(API_LATE_SECONDS * 1000)
    page.click("#call-api")
    page.wait_for_load_state("load")
    page.locator("#api-ok, #api-error").first.wait_for(timeout=10000)
    if page.locator("#api-ok").count():
        return f"{app}:login-ok", page.inner_text("body")
    return f"{app}:api-error", page.inner_text("body")


def call_api_from_browser(page, app):
    """After the login: the debug page's own script calls the API, cross-origin."""
    console = []
    page.on("console", lambda msg: console.append(f"{msg.type}: {msg.text}"))
    page.click("#call-api-browser")
    page.locator("#api-browser-ok, #api-browser-error").first.wait_for(timeout=10000)
    page.wait_for_timeout(500)  # let the console catch up with the page
    # Console messages name URLs and origins, never the token.
    print(f"[{app}] browser console: {len(console)} message(s)")
    for line in console:
        print(f"[{app}]   {line}")
    text = page.inner_text("body") + "\nBrowser console:\n" + "\n".join(console)
    if page.locator("#api-browser-ok").count():
        return f"{app}:login-ok", text
    return f"{app}:api-error", text


def app_error_shown(page):
    try:
        return page.locator("#error-message").count() > 0
    except Exception:  # noqa: BLE001 - the page is mid-navigation; look again
        return False


def excerpt(text, n=600):
    text = re.sub(r"\s+", " ", text).strip()
    return text[:n] + ("..." if len(text) > n else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("app", choices=APPS)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--expect", choices=["ok"])
    g.add_argument("--expect-error", metavar="TEXT")
    a = ap.parse_args()
    sys.exit(run(a.app, a.expect_error))


if __name__ == "__main__":
    main()
