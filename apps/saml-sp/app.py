"""SAML 2.0 service provider sample app for identity-lab.

Signs in against the Keycloak "idlab" realm with python3-saml and shows a
debug page with the decoded assertion. Failures are shown verbatim on an
error page and logged as a single key=value line so runbooks can grep them.
"""

import base64
import re
import datetime as dt
import logging
import os
import secrets
import shlex
import threading
from collections import OrderedDict

from cryptography import x509
from flask import Flask, redirect, render_template, request, session, url_for
from lxml import etree
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.constants import OneLogin_Saml2_Constants as C
from onelogin.saml2.errors import OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.settings import OneLogin_Saml2_Settings

LAB_HOST = os.environ["LAB_HOST"]
SP_BASE = f"https://{LAB_HOST}:{os.environ['SAML_SP_PORT']}"
IDP_ENTITY_ID = f"https://{LAB_HOST}:{os.environ['KC_PORT']}/realms/idlab"
IDP_SSO_URL = f"{IDP_ENTITY_ID}/protocol/saml"
# The IdP signing certificate(s) this SP trusts, pinned at onboarding the way
# most SaaS SPs store a pasted IdP certificate (scripts/pin-idp-cert.sh).
# Re-read on every login so a re-pin takes effect without a restart.
IDP_CERT_FILE = os.environ.get("IDP_CERT_FILE", "/var/lib/idlab/state/idp-signing.pem")
SP_CERT = open(os.environ.get("SP_CERT_FILE", "/etc/idlab/sp-signing.crt")).read()
SP_KEY = open(os.environ.get("SP_KEY_FILE", "/etc/idlab/sp-signing.key")).read()

app = Flask(__name__)
app.secret_key = os.environ["SAML_SP_SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_NAME="saml_sp_session",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s saml-sp %(message)s")
log = logging.getLogger("saml-sp")


def kv(**fields):
    return " ".join(f"{k}={shlex.quote(str(v))}" for k, v in fields.items())


# Decoded logins kept server-side: a SAML response is too big for a cookie.
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


class LoginError(Exception):
    def __init__(self, reason, message, detail=None, status=401):
        super().__init__(message)
        self.reason, self.message, self.detail, self.status = reason, message, detail, status


def describe_cert(b64):
    cert = x509.load_der_x509_certificate(base64.b64decode(b64))
    return {
        "b64": b64,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "expired": cert.not_valid_after_utc <= now_utc(),
        "not_yet_valid": cert.not_valid_before_utc > now_utc(),
    }


def pinned_idp_certs():
    """IdP signing certificates pinned on this SP."""
    try:
        pem = open(IDP_CERT_FILE).read()
    except FileNotFoundError:
        pem = ""
    bodies = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S)
    certs = [describe_cert("".join(body.split())) for body in bodies]
    if not certs:
        raise LoginError(
            "idp_cert_not_configured",
            "No IdP signing certificate is configured on this SP",
            f"{IDP_CERT_FILE} is missing or empty; run scripts/pin-idp-cert.sh",
            500,
        )
    return certs


def saml_settings(trusted_certs):
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": f"{SP_BASE}/saml/metadata",
            "assertionConsumerService": {"url": f"{SP_BASE}/saml/acs", "binding": C.BINDING_HTTP_POST},
            "NameIDFormat": C.NAMEID_EMAIL_ADDRESS,
            "x509cert": SP_CERT,
            "privateKey": SP_KEY,
        },
        "idp": {
            "entityId": IDP_ENTITY_ID,
            "singleSignOnService": {"url": IDP_SSO_URL, "binding": C.BINDING_HTTP_REDIRECT},
            "x509certMulti": {"signing": [c["b64"] for c in trusted_certs]},
        },
        "security": {
            "authnRequestsSigned": True,
            "wantMessagesSigned": True,
            "wantAssertionsSigned": True,
            "signatureAlgorithm": C.RSA_SHA256,
            "digestAlgorithm": C.SHA256,
            "rejectDeprecatedAlgorithm": True,
        },
    }


def trusted_signing_certs():
    """IdP certificates that are valid right now.

    python3-saml verifies signatures but ignores certificate validity dates.
    Like SPs that enforce them, this app refuses expired certificates, and
    says so plainly when none are left.
    """
    certs = pinned_idp_certs()
    valid = [c for c in certs if not c["expired"] and not c["not_yet_valid"]]
    if not valid:
        newest = max(certs, key=lambda c: c["not_after"]) if certs else None
        detail = (
            f"subject={newest['subject']} serial={newest['serial']} "
            f"notAfter={newest['not_after']:%Y-%m-%d %H:%M:%S} UTC "
            f"sp_clock={now_utc():%Y-%m-%d %H:%M:%S} UTC"
            if newest else "no IdP signing certificate pinned"
        )
        when = f" on {newest['not_after']:%Y-%m-%d %H:%M:%S} UTC" if newest else ""
        raise LoginError(
            "idp_cert_expired",
            f"IdP signing certificate expired{when}; the SP has no valid IdP certificate pinned",
            detail,
        )
    return certs, valid


def saml_request_data():
    return {
        "https": "on",
        "http_host": request.host,
        "script_name": request.path,
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
    }


def assertion_details(xml):
    ns = {"saml": C.NS_SAML, "samlp": C.NS_SAMLP, "ds": C.NS_DS}
    root = etree.fromstring(xml.encode() if isinstance(xml, str) else xml)

    def first(path, attr=None):
        found = root.xpath(path, namespaces=ns)
        if not found:
            return None
        return found[0].get(attr) if attr else found[0].text

    return {
        "issuer": first("//saml:Assertion/saml:Issuer"),
        "issue_instant": first("//saml:Assertion", "IssueInstant"),
        "not_before": first("//saml:Conditions", "NotBefore"),
        "not_on_or_after": first("//saml:Conditions", "NotOnOrAfter"),
        "audience": first("//saml:AudienceRestriction/saml:Audience"),
        "authn_instant": first("//saml:AuthnStatement", "AuthnInstant"),
        "response_signed": bool(root.xpath("/samlp:Response/ds:Signature", namespaces=ns)),
        "assertion_signed": bool(root.xpath("//saml:Assertion/ds:Signature", namespaces=ns)),
    }


@app.errorhandler(LoginError)
def login_error(exc):
    log.warning(kv(event="saml_login_failed", reason=exc.reason, error=exc.message, detail=exc.detail or ""))
    return render_template("error.html", error=exc, sp_clock=now_utc()), exc.status


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/")
def index():
    login = _logins.get(session.get("login_key", ""))
    return render_template("index.html", login=login, idp=IDP_ENTITY_ID)


@app.get("/login")
def login():
    # Expired certificates don't stop the AuthnRequest; the SP only
    # notices when the signed response comes back.
    auth = OneLogin_Saml2_Auth(saml_request_data(), saml_settings(pinned_idp_certs()))
    target = auth.login(return_to=url_for("debug", _external=False))
    session["authn_request_id"] = auth.get_last_request_id()
    log.info(kv(event="saml_authn_request", request_id=auth.get_last_request_id()))
    return redirect(target)


@app.post("/saml/acs")
def acs():
    all_certs, valid_certs = trusted_signing_certs()
    auth = OneLogin_Saml2_Auth(saml_request_data(), saml_settings(valid_certs))
    try:
        auth.process_response(request_id=session.pop("authn_request_id", None))
    except (OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError) as exc:
        # Some checks raise instead of populating get_errors().
        raise LoginError("invalid_response", str(exc), f"exception={type(exc).__name__}")
    errors = auth.get_errors()
    if errors:
        raise LoginError(
            "invalid_response",
            auth.get_last_error_reason() or ", ".join(errors),
            f"errors={','.join(errors)} sp_clock={now_utc():%Y-%m-%d %H:%M:%S} UTC",
        )
    xml = auth.get_last_response_xml(pretty_print_if_possible=True)
    key = store_login({
        "name_id": auth.get_nameid(),
        "name_id_format": auth.get_nameid_format(),
        "session_index": auth.get_session_index(),
        "attributes": auth.get_attributes(),
        "details": assertion_details(auth.get_last_response_xml()),
        "certs": all_certs,
        "xml": xml.decode() if isinstance(xml, bytes) else xml,
        "received_at": now_utc(),
    })
    session["login_key"] = key
    log.info(kv(event="saml_login_ok", name_id=auth.get_nameid(), assertion_id=auth.get_last_assertion_id()))
    return redirect(url_for("debug"))


@app.get("/debug")
def debug():
    login = _logins.get(session.get("login_key", ""))
    if not login:
        return redirect(url_for("index"))
    return render_template("debug.html", login=login, sp_clock=now_utc())


@app.get("/saml/metadata")
def metadata():
    settings = OneLogin_Saml2_Settings(saml_settings([]), sp_validation_only=True)
    return settings.get_sp_metadata(), 200, {"Content-Type": "application/xml"}


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))
