"""Gunicorn access log that masks one-time login values.

Authorisation codes, OAuth state, session_state, SAML messages and, from a
careless client, bearer tokens ride in query strings, and the default access
log would keep them in the container log for anyone who can read it. Their values are replaced with *** in the
request line, the query string and the Referer; parameter names stay, so a
log line still shows which step of the login it was. (The same module is in
apps/saml-sp, apps/oidc-rp and apps/api; keep them alike.)
"""

import re

from gunicorn.glogging import Logger

ONE_TIME = re.compile(r"(?<![^?&])(code|state|session_state|SAMLRequest|SAMLResponse|access_token)=[^&\s\"]+")


def mask(value):
    return ONE_TIME.sub(r"\1=***", value) if isinstance(value, str) else value


class MaskingLogger(Logger):
    def atoms(self, resp, req, environ, request_time):
        atoms = super().atoms(resp, req, environ, request_time)
        # request line, query string, Referer (also as the {referer}i header atom)
        for key in ("r", "q", "f", "{referer}i"):
            if key in atoms:
                atoms[key] = mask(atoms[key])
        return atoms
