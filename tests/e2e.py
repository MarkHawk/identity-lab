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

With E2E_OTP=stdin (an MFA user such as grace), Keycloak's one-time code
form is expected after the password, and the code is read from stdin, one
per line, as scripts/test.sh passes it from the authenticator app. Without
it, the flow is exactly as before.

With E2E_ENROL=1 (a new starter such as ivan), Keycloak's Mobile
Authenticator Setup page is expected after the password. e2e.py plays an
authenticator app that, like many, ignores the algorithm and digits in the
enrolment: it reads the key in the page's manual mode and types an
HMAC-SHA1, 6-digit, 30-second code from it (the lab authenticator's own
code, authenticator.py). It prints what the page asked for. The key is
removed from the page before the screenshot and HTML are saved, and the
saved HTML is checked for it. It never appears on the command line, in the output or
in the saved page.

Each run uses a fresh browser context (no Keycloak SSO session carried
over), signs in as a demo user (E2E_USER, default alice; LDAP users such as
dave work the same way), and checks where the flow ends up. Exit
status 0 means the expectation held. A screenshot and the final page HTML
are written to /results on every run.
"""

import argparse
import base64
import os
import re
import sys
import time
from urllib.parse import urlsplit

from playwright.sync_api import Error as PWError
from playwright.sync_api import TimeoutError as PWTimeout
from playwright.sync_api import sync_playwright

import authenticator  # the lab's authenticator app (apps/authenticator), for its TOTP code

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
OTP_FROM_STDIN = os.environ.get("E2E_OTP") == "stdin"
ENROL = os.environ.get("E2E_ENROL") == "1"
# Keys read from a setup page during this run: scrubbed from the evidence,
# and the saved HTML checked for them. Never printed.
SETUP_KEYS = []
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
                scrub_setup_key(page)
                page.screenshot(path=f"{RESULTS}/{stamp}.png", full_page=True)
                html = page.content()
                leaked = any(k in html or k.lower() in html for k in SETUP_KEYS)
                if leaked:
                    html = "<!-- not saved: it still held an authenticator setup key -->"
                with open(f"{RESULTS}/{stamp}.html", "w") as fh:
                    fh.write(html)
                if SETUP_KEYS:
                    print(f"[{app}] authenticator setup key kept out of the saved page: {not leaked}")
                    if leaked:
                        outcome = (f"{app}:evidence-error", "setup key still on the page after scrubbing")
            except Exception:  # noqa: BLE001 - evidence capture is best effort
                pass
            SETUP_KEYS.clear()
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
            raise PWTimeout(f"no Keycloak page after Log in; still at {without_query(page.url)}")
        page.wait_for_timeout(250)
    page.wait_for_load_state("load")
    if page.locator("#username").count() == 0:
        return "keycloak:error", page.inner_text("body")
    page.fill("#username", USER)
    page.fill("#password", PASSWORD)
    page.click("#kc-login")
    otp = otp_step(page, base) if OTP_FROM_STDIN else None
    if otp is None and ENROL:
        otp = enrol_step(page, base)
    if otp is not None:
        return otp
    try:
        page.wait_for_url(re.compile("^" + re.escape(base)), timeout=20000)
        page.wait_for_load_state("load")
    except PWTimeout:
        return f"stuck:{without_query(page.url)}", page.inner_text("body")
    if not page.locator("#login-ok").count():
        return f"{app}:error", page.inner_text("body")
    if app.startswith("oidc-api"):
        return call_api(page, app)
    if app == "oidc-token":
        return fetch_token(page, app, base)
    if app == "oidc-cors":
        return call_api_from_browser(page, app)
    return f"{app}:login-ok", page.inner_text("body")


def otp_step(page, base, timeout=20):
    """Keycloak's one-time code form, if it asks for one: type the next code.

    Returns None to carry on (no code asked for, or the code was accepted),
    or the (where, text) outcome when Keycloak refused the code or asked for
    one that wasn't given.
    """
    deadline = time.monotonic() + timeout
    while page.locator("#otp").count() == 0:
        if page.url.startswith(base + "/") or time.monotonic() > deadline:
            return None  # no code asked for: the caller handles the rest
        # The password form again, with an error (a wrong password, or a
        # locked account, which Keycloak words the same way on purpose).
        if page.locator("#kc-form-login #password").count() and page.locator('[id^="input-error"]').count():
            return "keycloak:password-refused", page.inner_text("body")
        page.wait_for_timeout(250)
    code = sys.stdin.readline().strip()
    if not code:
        return "keycloak:otp-asked", "Keycloak asked for a one-time code, but none was given\n" + page.inner_text("body")
    page.fill("#otp", code)
    del code
    page.click("#kc-login")
    deadline = time.monotonic() + timeout
    while not page.url.startswith(base + "/"):
        if page.locator("#otp").count() and page.locator('[id^="input-error"]').count():
            return "keycloak:otp-error", page.inner_text("body")
        if time.monotonic() > deadline:
            return None
        page.wait_for_timeout(250)
    return None


def enrol_step(page, base, timeout=20):
    """Keycloak's Mobile Authenticator Setup page: enrol, as an app that
    ignores the enrolment's algorithm and digits (most apps, in practice).

    Returns None when the setup was accepted, or the (where, text) outcome
    when Keycloak refused the code or showed no setup page.
    """
    deadline = time.monotonic() + timeout
    while page.locator("#kc-totp-settings-form").count() == 0:
        if page.url.startswith(base + "/") or time.monotonic() > deadline:
            return "keycloak:no-setup-page", page.inner_text("body")
        page.wait_for_timeout(250)
    # "Unable to scan?": the key as text, and the values the IdP asks for.
    page.click("#mode-manual")
    page.wait_for_load_state("load")
    page.locator("#kc-totp-secret-key").wait_for(timeout=10000)
    key = page.inner_text("#kc-totp-secret-key").replace(" ", "").strip()
    SETUP_KEYS.append(key)
    asked = [page.inner_text(f"#kc-totp-{f}").strip() for f in ("algorithm", "digits", "period")
             if page.locator(f"#kc-totp-{f}").count()]
    print(f"[enrol] the setup page asks for: {', '.join(asked)}")
    code = authenticator.totp(base64.b32decode(key.upper() + "=" * (-len(key) % 8)), time.time())
    del key
    page.fill("#totp", code)
    del code
    page.fill("#userLabel", "Lab authenticator")
    page.click("#saveTOTPBtn")
    deadline = time.monotonic() + timeout
    while not page.url.startswith(base + "/"):
        if page.locator("#kc-totp-settings-form").count() and page.locator('[id^="input-error"]').count():
            return "keycloak:setup-refused", page.inner_text("body") + "\nThe setup page asked for: " + ", ".join(asked)
        if time.monotonic() > deadline:
            return None
        page.wait_for_timeout(250)
    return None


def scrub_setup_key(page):
    """Take an authenticator setup key off the page: its text, the hidden
    form field and the QR code (it encodes the same key)."""
    page.evaluate(
        """() => {
            document.querySelectorAll('#kc-totp-secret-key').forEach(e => { e.textContent = '(removed by e2e.py)'; });
            document.querySelectorAll('#totpSecret').forEach(e => { e.setAttribute('value', ''); e.value = ''; });
            document.querySelectorAll('#kc-totp-secret-qr-code').forEach(e => { e.removeAttribute('src'); });
        }"""
    )


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


def without_query(url):
    """A URL fit to print: no query or fragment. Keycloak's login-action URLs
    carry one-time values (client_data, session_code, tab_id, execution),
    and an app's callback URL carries the code and state."""
    return urlsplit(url)._replace(query="", fragment="").geturl()


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
