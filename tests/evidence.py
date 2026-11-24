"""Browser evidence for e2e.py: a redacted HAR, a cookie jar summary and the
browser console, saved next to each run's screenshot and page HTML.

A support engineer reading them can follow the whole login: every URL,
method, status code, redirect, header name, Set-Cookie attribute (name,
domain, path, Secure, HttpOnly, SameSite, expiry) and timing. They never
hold a secret:

- cookie values (Cookie and Set-Cookie headers, the HAR's cookie lists) are
  replaced with <redacted>, keeping each cookie's name and attributes
- Authorization and Proxy-Authorization keep their scheme only
- one-time and signed values in URLs (QUERY_NAMES: code, state, SAMLRequest,
  Signature, Keycloak's session_code and client_data, ...) become name=***,
  as the reverse proxy masks them in its log
- form fields are masked, except a few that only name the user or the
  button (FORM_KEEP); so passwords, one-time codes, SAMLResponse and
  RelayState are
- response bodies are never recorded (record_har_content="omit"), and any
  that are left are dropped: the token endpoint's answer, a page with an
  auto-posting SAML form

The raw HAR Playwright writes is unredacted. e2e.py writes it to a
temporary folder inside the container, never to the mounted /results, and
deletes it whatever happens.

Refused cookies come from Chromium's DevTools protocol (Network and Audits
events), so they are Chromium-only. A cookie that a Set-Cookie header set
but that never reached the jar is also reported, as "inferred".

    python3 evidence.py selftest    redact a made-up HAR and check the result
"""

import datetime as dt
import json
import re
import sys
from urllib.parse import parse_qsl, quote, urlsplit

MASK = "***"
REDACTED = "<redacted>"
# Query (and fragment) parameters whose values are one-time, signed or
# secret. Compared without regard to case.
QUERY_NAMES = (
    "code", "state", "session_state", "id_token_hint", "id_token", "access_token", "refresh_token",
    "SAMLRequest", "SAMLResponse", "RelayState", "Signature",
    "nonce", "code_challenge", "code_verifier", "session_code", "client_data", "tab_id",
    "password", "otp", "totp", "client_secret", "token",
)
_QUERY_RE = re.compile(r"([?&#;])(" + "|".join(map(re.escape, QUERY_NAMES)) + r")=([^&#\s\"']*)", re.I)
# Form fields kept as they are: they name the user or the button pressed.
FORM_KEEP = {"username", "login", "credentialid", "rememberme"}
_QUERY_LOWER = {n.lower() for n in QUERY_NAMES}


def mask_url(text):
    """Mask the values of QUERY_NAMES wherever they appear as name=value."""
    if not isinstance(text, str):
        return text
    return _QUERY_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}={MASK}", text)


def cookie_names_only(header):
    """Cookie: a=1; b=2  ->  a=<redacted>; b=<redacted>"""
    parts = [p.strip() for p in header.split(";") if p.strip()]
    return "; ".join(f"{p.split('=', 1)[0].strip()}={REDACTED}" for p in parts)


def set_cookie_attributes(line):
    """Set-Cookie: name=value; Path=/; Secure  ->  name=<redacted>; Path=/; Secure"""
    name, _, rest = line.partition(";")
    name = name.split("=", 1)[0].strip()
    return f"{name}={REDACTED}" + (";" + rest if rest else "")


def parse_set_cookie(line):
    """Name and attributes of a Set-Cookie line, never its value."""
    first, _, rest = line.partition(";")
    attrs = {}
    for part in rest.split(";"):
        part = part.strip()
        if not part:
            continue
        k, eq, v = part.partition("=")
        attrs[k.strip().lower()] = v.strip() if eq else True
    out = {"name": first.split("=", 1)[0].strip()}
    for key, label in (("domain", "domain"), ("path", "path"), ("samesite", "sameSite"),
                       ("expires", "expires"), ("max-age", "maxAge")):
        if key in attrs:
            out[label] = attrs[key]
    out["secure"] = "secure" in attrs
    out["httpOnly"] = "httponly" in attrs
    return out


def is_deletion(cookie):
    """A Set-Cookie that removes the cookie (Max-Age <= 0, or Expires in the past)."""
    try:
        if "maxAge" in cookie:
            return int(cookie["maxAge"]) <= 0
    except ValueError:
        return False
    if "expires" in cookie:
        try:
            when = dt.datetime.strptime(cookie["expires"], "%a, %d %b %Y %H:%M:%S GMT")
            return when.replace(tzinfo=dt.timezone.utc) <= dt.datetime.now(dt.timezone.utc)
        except ValueError:
            return False
    return False


def _redact_header(h):
    name = h.get("name", "").lower()
    value = h.get("value", "")
    if name == "cookie":
        value = cookie_names_only(value)
    elif name == "set-cookie":
        value = "\n".join(set_cookie_attributes(v) for v in value.split("\n"))
    elif name in ("authorization", "proxy-authorization"):
        scheme = value.split(" ", 1)[0] if " " in value else ""
        value = f"{scheme} {REDACTED}".strip()
    else:
        value = mask_url(value)
    return {**h, "value": value}


def _mask_form_value(name, value):
    return value if name.lower() in FORM_KEEP else MASK


def _redact_post_data(pd):
    out = {k: v for k, v in pd.items() if k not in ("text", "params")}
    params = pd.get("params")
    if params:
        out["params"] = [{**p, "value": _mask_form_value(p.get("name", ""), p.get("value", ""))} for p in params]
    text = pd.get("text")
    if text is not None:
        if "application/x-www-form-urlencoded" in pd.get("mimeType", ""):
            pairs = parse_qsl(text, keep_blank_values=True)
            out["text"] = "&".join(
                f"{quote(k, safe='')}=" + (quote(v, safe="") if k.lower() in FORM_KEEP else MASK) for k, v in pairs)
        else:
            out["text"] = f"{REDACTED} ({len(text)} characters)"
    return out


def redact_entry(e):
    req, resp = dict(e.get("request", {})), dict(e.get("response", {}))
    req["url"] = mask_url(req.get("url", ""))
    req["headers"] = [_redact_header(h) for h in req.get("headers", [])]
    req["cookies"] = [{**c, "value": REDACTED} for c in req.get("cookies", [])]
    req["queryString"] = [
        {**q, "value": MASK if q.get("name", "").lower() in _QUERY_LOWER else q.get("value", "")}
        for q in req.get("queryString", [])]
    if "postData" in req:
        req["postData"] = _redact_post_data(req["postData"])
    resp["headers"] = [_redact_header(h) for h in resp.get("headers", [])]
    resp["cookies"] = [{**c, "value": REDACTED} for c in resp.get("cookies", [])]
    resp["redirectURL"] = mask_url(resp.get("redirectURL", ""))
    content = {k: v for k, v in resp.get("content", {}).items() if k not in ("text", "encoding", "_file")}
    resp["content"] = content
    return {**e, "request": req, "response": resp}


def redact_har(har):
    log = dict(har.get("log", {}))
    log["pages"] = [{**p, "title": mask_url(p.get("title", ""))} for p in log.get("pages", [])]
    log["entries"] = [redact_entry(e) for e in log.get("entries", [])]
    log["comment"] = ("Redacted by tests/evidence.py: cookie values, Authorization, one-time URL values, "
                      "form fields and response bodies removed")
    return {**har, "log": log}


def cookie_summary(cookie):
    """One cookie from the jar (Playwright's context.cookies()), without its value."""
    exp = cookie.get("expires", -1)
    return {
        "name": cookie.get("name"),
        "domain": cookie.get("domain"),
        "path": cookie.get("path"),
        "secure": cookie.get("secure"),
        "httpOnly": cookie.get("httpOnly"),
        "sameSite": cookie.get("sameSite"),
        "expires": "session" if exp is None or exp < 0
        else dt.datetime.fromtimestamp(exp, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def without_query(url):
    return urlsplit(url)._replace(query="", fragment="").geturl() if url else url


def _har_time(entry):
    try:
        return dt.datetime.fromisoformat(entry["startedDateTime"].replace("Z", "+00:00")).timestamp()
    except (KeyError, ValueError):
        return 0.0


def inferred_refused(har, jar_names, until=None):
    """Cookies a Set-Cookie header set (and didn't delete) that aren't in the
    jar: name, attributes and the response that set them. Looks at the
    responses started before `until` (epoch seconds), if given."""
    latest = {}
    for e in sorted(har.get("log", {}).get("entries", []), key=_har_time):
        if until is not None and _har_time(e) > until:
            continue
        for h in e.get("response", {}).get("headers", []):
            if h.get("name", "").lower() != "set-cookie":
                continue
            for line in h.get("value", "").split("\n"):
                c = parse_set_cookie(line)
                c["setBy"] = f"{e['request'].get('method')} {without_query(e['request'].get('url'))} " \
                             f"-> {e['response'].get('status')}"
                latest[c["name"]] = c
    return [{**c, "source": "inferred: set by a Set-Cookie header, not in the jar"}
            for name, c in latest.items() if name not in jar_names and not is_deletion(c)]


class Recorder:
    """Collects console messages, cookie jar snapshots and the cookies
    Chromium refused, for one browser context. Cookie values are kept in
    memory only, for the leak check in check_files(), and never written."""

    def __init__(self, context, page):
        self.context, self.page = context, page
        self.console, self.steps, self.refused = [], [], []
        self.values = set()
        page.on("console", lambda m: self.console.append(f"{m.type}: {mask_url(m.text)}"))
        page.on("pageerror", lambda err: self.console.append(f"pageerror: {mask_url(str(err))}"))
        try:
            cdp = context.new_cdp_session(page)
            cdp.send("Network.enable")
            cdp.send("Audits.enable")
            cdp.on("Network.responseReceivedExtraInfo", self._on_extra_info)
            cdp.on("Audits.issueAdded", self._on_issue)
            self.cdp = cdp
        except Exception:  # noqa: BLE001 - not Chromium: no refused-cookie reasons
            self.cdp = None

    def _on_extra_info(self, e):
        for b in e.get("blockedCookies", []):
            c = parse_set_cookie(b.get("cookieLine", ""))
            self.refused.append({**c, "reasons": b.get("blockedReasons", []),
                                 "source": "browser: Chromium DevTools protocol, Network.responseReceivedExtraInfo"})

    def _on_issue(self, e):
        issue = e.get("issue", {})
        if issue.get("code") != "CookieIssue":
            return
        d = issue.get("details", {}).get("cookieIssueDetails", {})
        cookie = d.get("cookie") or parse_set_cookie(d.get("rawCookieLine", ""))
        self.refused.append({
            "name": cookie.get("name"),
            "operation": d.get("operation"),
            "url": without_query(d.get("cookieUrl") or d.get("request", {}).get("url")),
            "exclusionReasons": d.get("cookieExclusionReasons", []),
            "warningReasons": d.get("cookieWarningReasons", []),
            "source": "browser: Chromium DevTools protocol, Audits.issueAdded (the Issues panel)",
        })

    def snapshot(self, step):
        try:
            jar = self.context.cookies()
            url = self.page.url
        except Exception:  # noqa: BLE001 - evidence capture is best effort
            return
        self.values.update(c["value"] for c in jar if len(c.get("value", "")) >= 8)
        self.steps.append({
            "step": step,
            "at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "_t": dt.datetime.now(dt.timezone.utc).timestamp(),
            "url": without_query(url),
            "cookies": [cookie_summary(c) for c in jar],
        })

    def summary(self, har):
        steps = []
        for s in self.steps:
            names = {c["name"] for c in s["cookies"]}
            steps.append({**{k: v for k, v in s.items() if k != "_t"},
                          "inferredRefused": inferred_refused(har, names, s["_t"]) if har else []})
        return {
            "comment": "Cookie names and attributes after each step of the login, never their values. "
                       "refusedByBrowser comes from Chromium's DevTools protocol (Chromium only); "
                       "inferredRefused compares the HAR's Set-Cookie headers with the jar.",
            "steps": steps,
            "refusedByBrowser": self.refused,
        }


def leaked(paths, values):
    """Paths among `paths` that contain any of `values`. Never prints them."""
    hits = []
    for p in paths:
        try:
            text = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if any(v and v in text for v in values):
            hits.append(p)
    return hits


# --- Self-test -------------------------------------------------------------------
# Made-up values, nothing from the lab: each must be gone from the redacted
# HAR, and the names, attributes and URLs a support engineer needs kept.
_FAKE = {
    "cookie": "fakeCookieValue0123456789",
    "cookie2": "anotherFakeValue98765",
    "bearer": "fakeBearerToken.abcdef.123456",
    "code": "fake-auth-code-1a2b3c",
    "state": "fakeStateValue77",
    "saml": "PHNhbWxwOlJlc3BvbnNlIGZha2U9InllcyIvPg==",
    "password": "fake-Passw0rd-not-real",
    "otp": "135791",
    "session_code": "fakeSessionCode42",
    "body": "fake.token.body.0f9e8d",
}


def _selftest_har():
    f = _FAKE
    return {"log": {"version": "1.2", "pages": [], "entries": [
        {"startedDateTime": "2026-11-24T10:00:00.000Z", "time": 12.5,
         "request": {"method": "GET", "url": f"https://idlab.example:8182/auth/callback?state={f['state']}&code={f['code']}",
                     "headers": [{"name": "Cookie", "value": f"oidc_rp_session={f['cookie']}; KC_X={f['cookie2']}"},
                                 {"name": "Authorization", "value": f"Bearer {f['bearer']}"},
                                 {"name": "Referer", "value": f"https://idlab.example:8180/x?session_code={f['session_code']}"}],
                     "cookies": [{"name": "oidc_rp_session", "value": f["cookie"]}],
                     "queryString": [{"name": "state", "value": f["state"]}, {"name": "code", "value": f["code"]}]},
         "response": {"status": 302, "redirectURL": f"/debug?code={f['code']}",
                      "headers": [{"name": "Set-Cookie",
                                   "value": f"saml_sp_session={f['cookie']}; HttpOnly; Path=/; SameSite=None"},
                                  {"name": "Location", "value": f"/debug?code={f['code']}"}],
                      "cookies": [{"name": "saml_sp_session", "value": f["cookie"]}],
                      "content": {"size": 34, "mimeType": "application/json", "text": "{\"access_token\":\"" + f["body"] + "\"}"}}},
        {"startedDateTime": "2026-11-24T10:00:01.000Z", "time": 3.0,
         "request": {"method": "POST", "url": "https://idlab.example:8181/saml/acs", "headers": [], "cookies": [],
                     "queryString": [],
                     "postData": {"mimeType": "application/x-www-form-urlencoded",
                                  "text": f"SAMLResponse={quote(f['saml'], safe='')}&RelayState=%2Fdebug&username=alice"
                                          f"&password={f['password']}&otp={f['otp']}",
                                  "params": [{"name": "SAMLResponse", "value": f["saml"]},
                                             {"name": "username", "value": "alice"},
                                             {"name": "password", "value": f["password"]},
                                             {"name": "otp", "value": f["otp"]}]}},
         "response": {"status": 302, "headers": [], "cookies": [], "content": {"size": 0}}},
    ]}}


def selftest():
    har = _selftest_har()
    out = json.dumps(redact_har(har))
    problems = [f"{k} still present" for k, v in _FAKE.items() if v in out or quote(v, safe="") in out]
    for kept in ("saml_sp_session=<redacted>; HttpOnly; Path=/; SameSite=None",
                 "oidc_rp_session=<redacted>; KC_X=<redacted>", "Bearer <redacted>",
                 "/auth/callback?state=***&code=***", "session_code=***", "username=alice",
                 '"status": 302', '"mimeType": "application/json"'):
        if kept not in out:
            problems.append(f"expected to keep: {kept}")
    names = {c["name"] for c in inferred_refused(har, set())}
    if names != {"saml_sp_session"}:
        problems.append(f"inferred refused cookies: {sorted(names)}, expected ['saml_sp_session']")
    print(f"redaction self-test: {len(_FAKE)} made-up values, {len(problems)} problem(s)")
    for p in problems:
        print(f"  {p}")
    return 1 if problems else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["selftest"]:
        sys.exit(selftest())
    print(__doc__.strip().splitlines()[-1].strip())
    sys.exit(2)
