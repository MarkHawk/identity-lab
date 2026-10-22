"""OpenID Connect relying party sample app for identity-lab.

Signs in against the Keycloak "idlab" realm with Authlib (authorization
code flow + PKCE, confidential client) and shows a debug page with the
decoded ID token. Failures are shown verbatim on an error page and logged
as a single key=value line so runbooks can grep them.
"""

import base64
import datetime as dt
import json
import logging
import os
import secrets
import shlex
import threading
import time
from collections import OrderedDict

import requests
from authlib.common.errors import AuthlibBaseError
from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from accesslog import mask

LAB_HOST = os.environ["LAB_HOST"]
RP_BASE = f"https://{LAB_HOST}:{os.environ['OIDC_RP_PORT']}"
REDIRECT_URI = f"{RP_BASE}/auth/callback"
# Discovery goes over the compose network. Keycloak takes its hostname from
# KC_HOSTNAME (LAB_HOST) and the port from the request, so it answers with
# the browser-facing issuer and endpoints, https://LAB_HOST:KC_PORT/...
# LAB_HOST may be localhost, which inside this container is the container
# itself, so the endpoints this app calls directly (token, userinfo, JWKS)
# are rewritten to BACKCHANNEL_BASE. The issuer and the authorization
# endpoint the browser is sent to are left alone.
BACKCHANNEL_BASE = os.environ.get("OIDC_BACKCHANNEL_BASE", "https://keycloak:8180")
DISCOVERY_URL = os.environ.get(
    "OIDC_DISCOVERY_URL", f"{BACKCHANNEL_BASE}/realms/idlab/.well-known/openid-configuration"
)
FRONTCHANNEL_BASE = f"https://{LAB_HOST}:{os.environ['KC_PORT']}"
BACKCHANNEL_ENDPOINTS = ("token_endpoint", "userinfo_endpoint", "jwks_uri")
# Extra seconds the callback takes before it redeems the code, standing in
# for a slow token endpoint or database behind the app. Re-read on every
# request; only the copy behind the reverse proxy has the file
# (scenarios/proxy-gateway-timeout.sh).
DELAY_FILE = os.environ.get("OIDC_RP_DELAY_FILE")
# Compose service name, for the log hint on the error page.
SERVICE = os.environ.get("OIDC_RP_SERVICE", "oidc-rp")
# Only oidc-rp-edge sets these: TLS ends at the reverse proxy, which talks
# plain HTTP to the app. The app takes the scheme from X-Forwarded-Proto set
# by that many proxies in front of it, and redirects any request that still
# looks like plain HTTP to https, as apps behind a TLS-terminating load
# balancer usually do (scenarios/redirect-loop.sh).
PROXY_HOPS = int(os.environ.get("OIDC_RP_PROXY_HOPS", "0"))
# The API (resource server) this app calls with the user's access token,
# from the debug page. Only the direct copy sets it (scenarios/api-bearer-*.sh).
API_URL = os.environ.get("OIDC_RP_API_URL")
# The same API as the browser reaches it (its public URL), for "Call the API
# from the browser" on the debug page: a cross-origin call, so CORS applies
# (scenarios/cors-blocked.sh). Only the direct copy sets it.
API_BROWSER_URL = os.environ.get("OIDC_RP_API_BROWSER_URL")
FORCE_HTTPS = os.environ.get("OIDC_RP_FORCE_HTTPS") == "1"

app = Flask(__name__)
app.secret_key = os.environ["OIDC_RP_SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_NAME="oidc_rp_session",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

if PROXY_HOPS:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=PROXY_HOPS, x_proto=PROXY_HOPS)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s oidc-rp %(message)s")
log = logging.getLogger("oidc-rp")

oauth = OAuth(app)
oauth.register(
    "keycloak",
    client_id=os.environ.get("OIDC_CLIENT_ID", "oidc-rp"),
    client_secret=os.environ["OIDC_CLIENT_SECRET"],
    server_metadata_url=DISCOVERY_URL,
    client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"},
)
_load_server_metadata = oauth.keycloak.load_server_metadata


def load_server_metadata():
    metadata = _load_server_metadata()
    for key in BACKCHANNEL_ENDPOINTS:
        url = metadata.get(key, "")
        if url.startswith(FRONTCHANNEL_BASE + "/"):
            metadata[key] = BACKCHANNEL_BASE + url[len(FRONTCHANNEL_BASE):]
    return metadata


oauth.keycloak.load_server_metadata = load_server_metadata


def kv(**fields):
    return " ".join(f"{k}={shlex.quote(str(v))}" for k, v in fields.items())


# Decoded logins kept server-side so tokens never sit in a cookie.
# One gunicorn worker, so an in-process store is enough for a lab.
_logins = OrderedDict()
_logins_lock = threading.Lock()


def callback_delay():
    if not DELAY_FILE:
        return 0.0
    try:
        with open(DELAY_FILE) as fh:
            return max(0.0, float(fh.read().strip() or 0))
    except (OSError, ValueError):
        return 0.0


def store_login(data):
    key = secrets.token_urlsafe(16)
    with _logins_lock:
        _logins[key] = data
        while len(_logins) > 50:
            _logins.popitem(last=False)
    return key


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def jwt_part(token, index):
    seg = token.split(".")[index]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def fmt_epoch(value):
    try:
        return dt.datetime.fromtimestamp(int(value), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return None


class LoginError(Exception):
    def __init__(self, reason, message, detail=None, status=401):
        super().__init__(message)
        self.reason, self.message, self.detail, self.status = reason, message, detail, status


@app.errorhandler(LoginError)
def login_error(exc):
    # One-time values (state, code) are masked in the log, as in the access
    # log; the error page still shows them to the user who hit the error.
    log.warning(kv(event="oidc_login_failed", reason=exc.reason, error=mask(exc.message), detail=mask(exc.detail or "")))
    return render_template("error.html", error=exc, rp_clock=now_utc(), service=SERVICE), exc.status


@app.before_request
def force_https():
    if not FORCE_HTTPS or request.is_secure or request.path == "/healthz":
        return None
    # The path only: the query string can carry an authorisation code.
    log.info(kv(
        event="force_https", path=request.path, scheme=request.scheme,
        x_forwarded_proto=request.headers.get("X-Forwarded-Proto", "-"),
    ))
    # To the app's own public URL, not one built from the Host header, which
    # the client controls. 302, not 301: browsers cache a 301, and would keep
    # looping after the fix.
    query = request.query_string.decode()
    return redirect(RP_BASE + request.path + ("?" + query if query else ""), code=302)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/")
def index():
    login = _logins.get(session.get("login_key", ""))
    return render_template("index.html", login=login, redirect_uri=REDIRECT_URI)


@app.get("/login")
def login():
    log.info(kv(event="oidc_authorize_redirect", redirect_uri=REDIRECT_URI))
    try:
        # Loads discovery on first use (Authlib then keeps it for the life of
        # the process), so a broken back channel can show up here.
        return oauth.keycloak.authorize_redirect(REDIRECT_URI)
    except requests.RequestException as exc:
        raise LoginError("backchannel_failed", str(exc), f"{type(exc).__name__} fetching {DISCOVERY_URL}", status=502)


@app.get("/auth/callback")
def callback():
    started = time.monotonic()
    if "error" in request.args:
        # The IdP redirected back with an error instead of a code.
        raise LoginError(
            request.args["error"],
            request.args.get("error_description") or request.args["error"],
            f"state={request.args.get('state', '')}",
        )
    delay = callback_delay()
    if delay:
        time.sleep(delay)
    try:
        token = oauth.keycloak.authorize_access_token()
    except requests.RequestException as exc:
        # The back channel itself failed (proxy, DNS, TLS), not the IdP's answer.
        raise LoginError("backchannel_failed", str(exc), type(exc).__name__, status=502)
    except AuthlibBaseError as exc:
        raise LoginError(exc.error or "oauth_error", exc.description or str(exc), type(exc).__name__)
    except Exception as exc:  # noqa: BLE001 - e.g. ID token claim validation (joserfc)
        raise LoginError("token_validation_failed", str(exc), type(exc).__name__)
    id_token = token.get("id_token", "")
    claims = dict(token.get("userinfo") or {})
    try:
        userinfo = oauth.keycloak.userinfo(token=token)
    except Exception as exc:  # noqa: BLE001 - show it, but the login itself succeeded
        userinfo = {"error": str(exc)}
    times = {k: fmt_epoch(claims.get(k)) for k in ("iat", "auth_time", "exp")}
    access_token = token.get("access_token", "")
    try:
        access_claims = jwt_part(access_token, 1)
    except (IndexError, ValueError):
        access_claims = {}
    key = store_login({
        # Kept only here, in memory, to call the API. Never logged, put in a
        # cookie or shown on a page (except /debug/access-token, on request).
        "access_token": access_token,
        "access_claims": {k: access_claims.get(k) for k in ("typ", "azp", "aud", "scope", "iss")},
        "access_times": {k: fmt_epoch(access_claims.get(k)) for k in ("iat", "exp")},
        "api": None,
        "header": jwt_part(id_token, 0) if id_token else {},
        "claims": claims,
        "times": times,
        "userinfo": dict(userinfo),
        "token_meta": {k: token.get(k) for k in ("token_type", "scope", "expires_in", "refresh_expires_in")},
        "received_at": now_utc(),
    })
    session["login_key"] = key
    log.info(kv(
        event="oidc_login_ok", sub=claims.get("sub"), email=claims.get("email"), iss=claims.get("iss"),
        elapsed=f"{time.monotonic() - started:.2f}s",
    ))
    return redirect(url_for("debug"))


@app.get("/debug")
def debug():
    login = _logins.get(session.get("login_key", ""))
    if not login:
        return redirect(url_for("index"))
    return render_template("debug.html", login=login, rp_clock=now_utc(), api_url=API_URL,
                           api_browser_url=API_BROWSER_URL)


@app.post("/api/call")
def call_api():
    login = _logins.get(session.get("login_key", ""))
    if not login or not API_URL:
        return redirect(url_for("index"))
    # The access token from login, as it is: this app doesn't refresh it.
    try:
        resp = requests.get(API_URL, headers={"Authorization": "Bearer " + login["access_token"]}, timeout=5)
        result = {
            "status": resp.status_code,
            "reason": resp.reason,
            "www_authenticate": resp.headers.get("WWW-Authenticate"),
            "body": resp.text[:2000],
        }
    except requests.RequestException as exc:
        result = {"status": None, "reason": f"{type(exc).__name__}: {exc}", "www_authenticate": None, "body": ""}
    result["at"] = now_utc()
    login["api"] = result
    log.info(kv(event="api_call", url=API_URL, status=result["status"] or "-",
                www_authenticate=result["www_authenticate"] or "-"))
    return redirect(url_for("debug") + "#api")


@app.get("/debug/access-token")
def raw_access_token():
    # The raw access token, for checking it offline with token-inspector, as
    # you would copy it from the browser's developer tools. Plain text, only
    # on request: no page embeds it, so saved page evidence never holds it.
    login = _logins.get(session.get("login_key", ""))
    if not login or not login.get("access_token"):
        abort(404)
    return login["access_token"] + "\n", 200, {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"}


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))
