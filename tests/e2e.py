"""Scripted browser logins against the identity-lab sample apps.

    e2e.py saml --expect ok
    e2e.py oidc --expect-error "Invalid parameter: redirect_uri"

Each run uses a fresh browser context (no Keycloak SSO session carried
over), signs in as a demo user, and checks where the flow ends up. Exit
status 0 means the expectation held. A screenshot and the final page HTML
are written to /results on every run.
"""

import argparse
import os
import re
import sys
import time

from playwright.sync_api import TimeoutError as PWTimeout
from playwright.sync_api import sync_playwright

LAB_HOST = os.environ["LAB_HOST"]
KC = f"https://{LAB_HOST}:{os.environ['KC_PORT']}"
APPS = {
    "saml": f"https://{LAB_HOST}:{os.environ['SAML_SP_PORT']}",
    "oidc": f"https://{LAB_HOST}:{os.environ['OIDC_RP_PORT']}",
}
USER = os.environ.get("E2E_USER", "alice")
PASSWORD = os.environ["DEMO_PASSWORD"]
EXPECTED_EMAIL = f"{USER}@idlab.example"
RESULTS = os.environ.get("RESULTS_DIR", "/results")


def run(app, expect_error=None):
    base = APPS[app]
    args = ["--disable-dev-shm-usage"]
    if LAB_HOST != "localhost":
        # Resolve LAB_HOST to this machine without relying on LAN DNS.
        args.append(f"--host-resolver-rules=MAP {LAB_HOST} 127.0.0.1")
    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=args)
        page = browser.new_context().new_page()
        try:
            outcome = flow(page, base)
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
        if f"{app}:login-ok" == where and EXPECTED_EMAIL in text:
            print(f"[{app}] PASS login succeeded for {EXPECTED_EMAIL}")
            return 0
        print(f"[{app}] FAIL expected a successful login; page says:\n{excerpt(text)}")
        return 1
    if where != f"{app}:login-ok" and expect_error in text:
        print(f"[{app}] PASS saw expected error: {expect_error!r}")
        return 0
    print(f"[{app}] FAIL expected error {expect_error!r}; page says:\n{excerpt(text)}")
    return 1


def flow(page, base):
    """Drive the login and report (where-we-ended-up, visible text)."""
    page.goto(base + "/", wait_until="load")
    page.click("#login")
    # Either Keycloak's login form, or a Keycloak error page (e.g. a bad
    # redirect_uri is rejected before any form is shown).
    page.wait_for_url(re.compile("^" + re.escape(KC)), timeout=15000)
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
    if page.locator("#login-ok").count():
        return f"{app_name(base)}:login-ok", page.inner_text("body")
    return f"{app_name(base)}:error", page.inner_text("body")


def app_name(base):
    return next(k for k, v in APPS.items() if v == base)


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
