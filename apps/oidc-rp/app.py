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
from collections import OrderedDict

from authlib.common.errors import AuthlibBaseError
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, render_template, request, session, url_for

LAB_HOST = os.environ["LAB_HOST"]
RP_BASE = f"https://{LAB_HOST}:{os.environ['OIDC_RP_PORT']}"
REDIRECT_URI = f"{RP_BASE}/auth/callback"
# Discovery goes over the compose network. Keycloak answers with a browser-
# facing authorization endpoint and issuer (LAB_HOST) and backchannel token,
# userinfo and JWKS endpoints (keycloak:8180).
DISCOVERY_URL = os.environ.get(
    "OIDC_DISCOVERY_URL", "https://keycloak:8180/realms/idlab/.well-known/openid-configuration"
)

app = Flask(__name__)
app.secret_key = os.environ["OIDC_RP_SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_NAME="oidc_rp_session",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

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


def kv(**fields):
    return " ".join(f"{k}={shlex.quote(str(v))}" for k, v in fields.items())


# Decoded logins kept server-side so tokens never sit in a cookie.
# One gunicorn worker, so an in-process store is enough for a lab.
_logins = OrderedDict()
_logins_lock = threading.Lock()


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
    log.warning(kv(event="oidc_login_failed", reason=exc.reason, error=exc.message, detail=exc.detail or ""))
    return render_template("error.html", error=exc, rp_clock=now_utc()), exc.status


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
    return oauth.keycloak.authorize_redirect(REDIRECT_URI)


@app.get("/auth/callback")
def callback():
    if "error" in request.args:
        # The IdP redirected back with an error instead of a code.
        raise LoginError(
            request.args["error"],
            request.args.get("error_description") or request.args["error"],
            f"state={request.args.get('state', '')}",
        )
    try:
        token = oauth.keycloak.authorize_access_token()
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
    key = store_login({
        "header": jwt_part(id_token, 0) if id_token else {},
        "claims": claims,
        "times": times,
        "userinfo": dict(userinfo),
        "token_meta": {k: token.get(k) for k in ("token_type", "scope", "expires_in", "refresh_expires_in")},
        "received_at": now_utc(),
    })
    session["login_key"] = key
    log.info(kv(event="oidc_login_ok", sub=claims.get("sub"), email=claims.get("email"), iss=claims.get("iss")))
    return redirect(url_for("debug"))


@app.get("/debug")
def debug():
    login = _logins.get(session.get("login_key", ""))
    if not login:
        return redirect(url_for("index"))
    return render_template("debug.html", login=login, rp_clock=now_utc())


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))
