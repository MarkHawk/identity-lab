"""API (resource server) for identity-lab that accepts Keycloak access tokens.

GET /v1/whoami with "Authorization: Bearer <access token>" answers with a
few of the token's claims. Before that, the token must be signed by a key in
the realm's JWKS, be an access token (typ Bearer), come from the expected
issuer, not have expired, and name this API in its audience (aud). Anything
else gets a 401 with an RFC 6750 WWW-Authenticate challenge saying why.

Every rejection is logged as a single key=value line with the claims that
decided it. The token itself is never logged, nor echoed in any response.

Browsers call it from another origin (the OIDC RP's debug page), so it
speaks CORS in two parts, the way an API behind a gateway often does. The
preflight (OPTIONS) is answered permissively for any origin, standing in
for a gateway that handles preflights itself. Real responses carry the
app's own Access-Control-Allow-Origin, from CORS_ORIGIN_FILE
(scenarios/cors-blocked.sh). The browser enforces CORS on both.
"""

import base64
import datetime as dt
import json
import logging
import os
import shlex
import threading
import time

import requests
from flask import Flask, jsonify, request
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

# The audience this API answers to; Keycloak adds it to the access tokens of
# clients that may call it (an audience mapper on the client).
AUDIENCE = os.environ.get("API_AUDIENCE", "idlab-api")
# Issuers whose tokens are accepted, space-separated: the public issuer
# Keycloak puts in tokens, https://LAB_HOST:KC_PORT/realms/idlab.
ISSUERS = os.environ.get(
    "API_ISSUERS", f"https://{os.environ['LAB_HOST']}:{os.environ['KC_PORT']}/realms/idlab"
).split()
# Signing keys, fetched over the compose network.
JWKS_URL = os.environ.get("API_JWKS_URL", "https://keycloak:8180/realms/idlab/protocol/openid-connect/certs")
REALM = "idlab-api"
# Seconds of clock difference allowed when checking exp.
LEEWAY = int(os.environ.get("API_LEEWAY", "0"))
# The Access-Control-Allow-Origin value for real (non-preflight) responses,
# one origin, re-read on every request. No file or an empty one: no header.
CORS_ORIGIN_FILE = os.environ.get("API_CORS_ORIGIN_FILE")

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s api %(message)s")
log = logging.getLogger("api")


def kv(**fields):
    return " ".join(f"{k}={shlex.quote(str(v))}" for k, v in fields.items())


def iso(value):
    try:
        return dt.datetime.fromtimestamp(int(value), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return "-"


def audiences(claims):
    aud = claims.get("aud", [])
    return [aud] if isinstance(aud, str) else list(aud)


def cors_allow_origin():
    """The app's configured Access-Control-Allow-Origin, or None."""
    if not CORS_ORIGIN_FILE:
        return None
    try:
        with open(CORS_ORIGIN_FILE) as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def is_preflight():
    return request.method == "OPTIONS" and "Access-Control-Request-Method" in request.headers


@app.before_request
def preflight():
    # The gateway's part: allow whatever origin asks, for GET with an
    # Authorization header. A browser sends this before a cross-origin call
    # that carries a token, and only sends the call if this allows it.
    if not is_preflight():
        return None
    origin = request.headers.get("Origin", "-")
    log.info(kv(event="api_cors_preflight", origin=origin,
                method=request.headers.get("Access-Control-Request-Method"),
                headers=request.headers.get("Access-Control-Request-Headers", "-")))
    return "", 204, {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET",
        "Access-Control-Allow-Headers": "Authorization",
        "Access-Control-Max-Age": "600",
        "Vary": "Origin",
    }


@app.after_request
def cors_headers(resp):
    # The app's part, on every real response (401s included, so a browser
    # page can read why it was refused).
    allow = cors_allow_origin()
    if allow and not is_preflight():
        resp.headers["Access-Control-Allow-Origin"] = allow
    return resp


class Rejected(Exception):
    """A request the API refuses: 401 with a WWW-Authenticate challenge."""

    def __init__(self, reason, description=None, claims=None):
        super().__init__(description or reason)
        self.reason, self.description, self.claims = reason, description, claims or {}


# The realm's signing keys, fetched on first use and again when a token
# names a key ID that isn't in the cached set (Keycloak rotated its keys),
# at most once every 30 seconds.
_keys = {"set": None, "kids": set(), "at": 0.0}
_keys_lock = threading.Lock()


def key_set(kid):
    with _keys_lock:
        stale = _keys["set"] is None or (kid not in _keys["kids"] and time.monotonic() - _keys["at"] > 30)
        if stale:
            data = requests.get(JWKS_URL, timeout=5).json()
            data["keys"] = [k for k in data.get("keys", []) if k.get("use", "sig") == "sig"]
            _keys["set"] = KeySet.import_key_set(data)
            _keys["kids"] = {k.get("kid") for k in data["keys"]}
            _keys["at"] = time.monotonic()
        return _keys["set"]


def bearer_token():
    header = request.headers.get("Authorization", "")
    scheme, _, value = header.partition(" ")
    if not header:
        # RFC 6750 3.1: no credentials at all gets a bare challenge, no error code.
        raise Rejected("no_token")
    if scheme.lower() != "bearer" or not value.strip():
        raise Rejected("invalid_request", "The Authorization header is not a Bearer token")
    return value.strip()


def validate(token):
    try:
        seg = token.split(".")[0]
        kid = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))).get("kid")
    except (ValueError, AttributeError):
        raise Rejected("invalid_token", "The access token is not a JWT")
    try:
        claims = jwt.decode(token, key_set(kid), algorithms=["RS256"]).claims
    except requests.RequestException as exc:
        log.warning(kv(event="api_jwks_failed", error=str(exc)))
        raise Rejected("invalid_token", "The API could not fetch the signing keys to check the token")
    except (JoseError, ValueError) as exc:
        raise Rejected("invalid_token", f"The access token could not be verified ({type(exc).__name__})")
    if claims.get("typ") != "Bearer":
        raise Rejected("invalid_token", f"This is not an access token (typ {claims.get('typ', 'missing')})", claims)
    if claims.get("iss") not in ISSUERS:
        raise Rejected("invalid_token", f"The access token issuer {claims.get('iss')} is not trusted", claims)
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or exp + LEEWAY < time.time():
        raise Rejected("invalid_token", f"The access token expired at {iso(exp)}", claims)
    aud = audiences(claims)
    if AUDIENCE not in aud:
        raise Rejected(
            "invalid_token",
            f"The access token audience ({' '.join(aud) or 'none'}) does not include {AUDIENCE}",
            claims,
        )
    return claims


@app.errorhandler(Rejected)
def rejected(exc):
    challenge = f'Bearer realm="{REALM}"'
    status = 401
    if exc.reason != "no_token":
        challenge += f', error="{exc.reason}", error_description="{exc.description}"'
        status = 400 if exc.reason == "invalid_request" else 401
    c = exc.claims
    log.warning(kv(
        event="api_token_rejected", error=exc.reason, error_description=exc.description or "-",
        sub=c.get("sub", "-"), azp=c.get("azp", "-"), aud=" ".join(audiences(c)) or "-", iss=c.get("iss", "-"),
        iat=iso(c.get("iat")) if c else "-", exp=iso(c.get("exp")) if c else "-",
    ))
    body = {"error": exc.reason}
    if exc.description:
        body["error_description"] = exc.description
    return jsonify(body), status, {"WWW-Authenticate": challenge, "Cache-Control": "no-store"}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/v1/whoami")
def whoami():
    claims = validate(bearer_token())
    # origin and cors_allow_origin: for a call from a browser page, what the
    # browser will compare. The API can't see whether the browser then
    # hands the response to the page.
    log.info(kv(event="api_request_ok", sub=claims.get("sub"), azp=claims.get("azp"),
                iat=iso(claims.get("iat")), exp=iso(claims.get("exp")),
                origin=request.headers.get("Origin", "-"), cors_allow_origin=cors_allow_origin() or "-"))
    return {
        "sub": claims.get("sub"),
        "preferred_username": claims.get("preferred_username"),
        "azp": claims.get("azp"),
        "scope": claims.get("scope"),
        "expires": iso(claims.get("exp")),
    }
