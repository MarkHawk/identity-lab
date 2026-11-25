"""Evidence packs for the support-training game: turn one capture of raw tool
output (scripts/evidence-packs.sh) into a redacted, time-normalised pack.

    python3 -I tests/packs.py build <raw-dir> <common-dir> <out.json>
    python3 -I tests/packs.py validate <packs-dir> <answers-dir>
    python3 -I tests/packs.py check-time <packs-dir> <answers-dir>
    python3 -I tests/packs.py selftest

Every line of every tool goes through, in order:

1. secrets: every value from .env (common/secrets, never printed) becomes
   <redacted>; JWTs, PEM blocks and SAML messages are removed; one-time URL
   values are masked with tests/evidence.py's mask_url, as in the HAR
2. placeholders: LAB_HOST becomes lab.example; each container's IP address
   becomes a fixed address in 192.0.2.0/24 (one per service and network, the
   same in every pack), each network's gateway (the host) one in
   198.51.100.0/24, any other IPv4 address 203.0.113.N; container IDs and
   names become service names; the repository path /srv/identity-lab; the
   host's name lab-host; Keycloak's user, client, component and realm IDs
   stable names (<user:alice>), and any other ID <id-N>, the same ID getting
   the same N within a pack
3. time: every timestamp moves by one delta, chosen so that the failing
   login starts at ANCHOR. Every format the lab's tools print is shifted
   (ISO 8601, nginx and Apache access log time, ctime, openssl dates, LDAP
   generalised time, slapd's hex epoch, epoch seconds and milliseconds), and
   relative statements ("600 s from the host", "expired 1 day before the
   login") are computed from the raw values first, so they stay true. A date
   with no time moves by whole days. The build fails if a raw date survives.

No answer: nothing here or in the raw capture names the scenario.
"""

import calendar
import datetime as dt
import difflib
import html.parser
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence  # noqa: E402  the HAR redaction's URL masking (tests/evidence.py)

FORMAT = "idlab-evidence-pack/1"
ANCHOR = dt.datetime(2026, 6, 14, 2, 14, 0, tzinfo=dt.timezone.utc)
TOOLS = [
    ("user-report", "What the user saw"),
    ("compose-ps", "Container status"),
    ("logs-keycloak", "Keycloak log"),
    ("keycloak-events", "Keycloak events"),
    ("logs-ldap", "OpenLDAP log"),
    ("logs-radius", "FreeRADIUS log"),
    ("logs-proxy", "Reverse proxy (nginx) log"),
    ("logs-squid", "Egress proxy (Squid) log"),
    ("logs-saml-sp", "SAML app log"),
    ("logs-saml-sp-proxied", "SAML app log (behind the proxy)"),
    ("logs-oidc-rp", "OIDC app log"),
    ("logs-oidc-rp-proxied", "OIDC app log (behind the proxy)"),
    ("logs-oidc-rp-egress", "OIDC app log (egress proxy)"),
    ("logs-oidc-rp-edge", "OIDC app log (edge)"),
    ("logs-api", "API log"),
    ("radius-test", "RADIUS test (radclient)"),
    ("clock", "Clock check"),
    ("token", "Token inspector"),
    ("trusted-keys", "Trusted keys and certificates"),
    ("ldap-user", "LDAP lookup"),
    ("recent-changes", "Recent changes"),
    ("browser-har", "Browser network log (HAR summary)"),
    ("browser-cookies", "Browser cookies"),
    ("browser-console", "Browser console"),
]
SEVERITIES = ("normal", "warning", "error")
CAP_LOG, CAP = 30, 40
# The one line every pack uses when its flow has no browser or no token, so
# the wording never hints at which kind of flow it was.
NO_BROWSER = "No browser in this flow"
NO_TOKEN = "No token in this flow"

# --- severity ------------------------------------------------------------------
# Whole words, then the markers that end in punctuation (so can't take a \b after them).
ERROR_RE = re.compile(
    r'\b(ERROR|FATAL|CRITICAL|Error|FAILED|[Ff]ailed|refused|[Dd]enied|DENIED|[Ii]nvalid|'
    r'[Ee]xpired|Access-Reject|not responding|Login incorrect|offset [+-]?\d{3,} s|'
    r'mismatch|[Mm]issing|absent|blocked|Unable|unable)\b|\berror=|_ERROR"|\berr=[1-9]')
WARN_RE = re.compile(r'\b(WARN|WARNING|[Ww]arning|timed out|timeout|retry|offset [+-]?[6-9]\d s)\b')
METHODS = r"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)"
# An HTTP request line, and where its status is: an access log ("GET /x HTTP/1.1" 200),
# the HAR summary (GET https://... -> 302) and Squid (TCP_TUNNEL/200 7077 CONNECT).
REQUEST_RES = (re.compile(r'"' + METHODS + r' [^"]*" (\d{3})\b'),
               re.compile(r"^\S+ " + METHODS + r" \S+ -> (\d{3})\b"),
               re.compile(r"\b[A-Z_]+/(\d{3}) \d+ " + METHODS + r" "))
# URLs and paths: never matched against the keywords ("/?session=expired" is a path, not an error).
URL_PATH_RE = re.compile(r"[a-z][a-z0-9+.-]*://\S+|\bpath=\S+|(?<![\w.])/[\w./?=&%*:~+-]*")


def severity(tool, text):
    """Severity from fixed rules: a request line by its HTTP status only (5xx
    error, 4xx warning); a changed setting is a warning; anything else by its
    log level, event type and wording, with URLs and paths left out."""
    if tool == "recent-changes" and text[:2] in ("- ", "+ "):
        return "warning"
    if tool == "browser-console":
        return "error" if text.startswith(("error:", "pageerror:")) else "warning" if text.startswith("warning:") else "normal"
    if text.lstrip().startswith("Set-Cookie:"):
        return "normal"
    for rx in REQUEST_RES:
        m = rx.search(text)
        if m:
            code = int(m.group(1))
            return "error" if code >= 500 else "warning" if code >= 400 else "normal"
    words = URL_PATH_RE.sub(" ", text)
    if ERROR_RE.search(words):
        return "error"
    if WARN_RE.search(words):
        return "warning"
    return "normal"


# --- secrets ---------------------------------------------------------------------
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")
PEM_RE = re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.S)
SAML_RE = re.compile(r"(SAMLRequest|SAMLResponse|RelayState)=[^*&\s\"']+|PHNhbWxwO[A-Za-z0-9+/=]*|PHNhbWw6[A-Za-z0-9+/=]*")


def scrub_secrets(text, secrets):
    for v in secrets:
        if v:
            text = text.replace(v, "<redacted>")
    text = JWT_RE.sub("<token removed>", text)
    text = PEM_RE.sub("<PEM block removed>", text)
    text = SAML_RE.sub(lambda m: (m.group(1) + "=***") if m.group(1) else "<SAML message removed>", text)
    return evidence.mask_url(text)


# --- placeholders ------------------------------------------------------------------
# (not \b: an ID_ or onltro: prefix is a word character)
UUID_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])")
# python3-saml's request IDs
ONELOGIN_RE = re.compile(r"ONELOGIN_[0-9a-f]{40}")
# Keycloak's own session-ish IDs, by field: sessionId="...", code_id="...", "sid": "..."
KC_ID_RE = re.compile(r'((?:sessionId|code_id|authSessionParentId|authSessionTabId|token_id|refresh_token_id|'
                      r'userSessionId|sid|session_state|jti)["\']?\s*[=:]\s*["\']?)([A-Za-z0-9:._-]{8,})')
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
KEEP_IPS = {"0.0.0.0"}  # and all of 127.0.0.0/8: loopback, inside a container or the host


class Placeholders:
    def __init__(self, common, ids):
        self.c = common
        self.ids = ids  # per pack: raw id -> <id-N>

    def other_id(self, raw):
        if raw not in self.ids:
            self.ids[raw] = f"<id-{len(self.ids) + 1}>"
        return self.ids[raw]

    def apply(self, text):
        c = self.c
        for raw, name in c["fixed"].items():  # Keycloak's users, clients, components, realm; container IDs
            text = text.replace(raw, name)
        text = KC_ID_RE.sub(lambda m: m.group(1) + (m.group(2) if m.group(2).startswith("<") else self.other_id(m.group(2))), text)
        text = UUID_RE.sub(lambda m: self.other_id(m.group(0)), text)
        text = ONELOGIN_RE.sub(lambda m: "ONELOGIN_" + self.other_id(m.group(0)), text)
        if c["lab_host"] and c["lab_host"] != "localhost":
            # also inside URL-encoded values: https%3A%2F%2F<host>%3A8180
            text = re.sub(r"(?:(?<![\w.-])|(?<=%2F)|(?<=%2f)|(?<=%40))" + re.escape(c["lab_host"]) + r"(?![\w-])",
                          "lab.example", text)
        text = text.replace(c["lab_root"], "/srv/identity-lab")
        if c.get("home"):
            text = text.replace(c["home"], "/home/user")
        if c.get("hostname"):
            text = re.sub(r"\b" + re.escape(c["hostname"]) + r"\b", "lab-host", text)
        for raw, name in c["containers"].items():
            text = text.replace(raw, name)

        def ip(m):
            a = m.group(0)
            if a in KEEP_IPS or a.startswith(("127.", "192.0.2.", "198.51.100.", "203.0.113.")):
                return a
            if a in c["ips"]:
                return c["ips"][a]
            unknown = c["unknown_ips"]
            if a not in unknown:
                unknown[a] = f"203.0.113.{len(unknown) + 1}"
                c["unknown_new"] = True
            return unknown[a]
        return IPV4_RE.sub(ip, text)


# --- time --------------------------------------------------------------------------
MON = {m: i for i, m in enumerate(calendar.month_abbr) if m}
DAY = list(calendar.day_abbr)  # Mon..Sun
LO, HI = 1_500_000_000, 2_500_000_000  # epoch seconds this lab can print: 2017 to 2049


class Shifter:
    """Moves every timestamp by `delta` seconds; dates with no time by `days`."""

    def __init__(self, delta, days):
        self.delta, self.days = delta, days
        self.n = 0

    def t(self, d):
        self.n += 1
        return d + dt.timedelta(seconds=self.delta)

    def shift(self, s):
        def iso(m):
            frac, tz = m.group("frac") or "", m.group("tz") or ""
            base = dt.datetime.strptime(m.group("d") + " " + m.group("t"), "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
            out = self.t(base)
            wd = m.group("wd")
            prefix = (DAY[out.weekday()] + " ") if wd else ""
            return f"{prefix}{out:%Y-%m-%d}{m.group('sep')}{out:%H:%M:%S}{frac}{tz}"
        s = re.sub(r"(?P<wd>\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) )?(?P<d>\d{4}-\d{2}-\d{2})(?P<sep>[T ])(?P<t>\d{2}:\d{2}:\d{2})"
                   r"(?P<frac>[.,]\d+)?(?P<tz>Z|[+-]\d{2}:?\d{2}| UTC| GMT)?", iso, s)

        def slash(m):  # nginx's error log and Squid's cache log: 2026/11/25 17:18:40
            out = self.t(dt.datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S").replace(tzinfo=dt.timezone.utc))
            return f"{out:%Y/%m/%d %H:%M:%S}"
        s = re.sub(r"(?<![\d/])(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", slash, s)

        def clf(m):
            out = self.t(dt.datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S").replace(tzinfo=dt.timezone.utc))
            return f"{out:%d/%b/%Y:%H:%M:%S} {m.group(2)}"
        s = re.sub(r"(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}) ([+-]\d{4})", clf, s)

        def java(m):  # Java's Date.toString(), in Keycloak's log: Wed Nov 25 17:15:09 GMT 2026
            mon, day, hms, year = m.group("mon"), int(m.group("day")), m.group("hms"), int(m.group("year"))
            out = self.t(dt.datetime(year, MON[mon], day, *map(int, hms.split(":")), tzinfo=dt.timezone.utc))
            return f"{DAY[out.weekday()]} {calendar.month_abbr[out.month]} {out.day:02d} {out:%H:%M:%S} {m.group('tz')} {out.year}"
        s = re.sub(r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?P<day>\d{2}) "
                   r"(?P<hms>\d{2}:\d{2}:\d{2}) (?P<tz>GMT|UTC) (?P<year>\d{4})\b", java, s)

        def ctime(m):  # Tue Nov 24 18:57:36 2026 (FreeRADIUS) and Nov 24 18:57:36 2026 GMT (openssl)
            mon, day, hms, year = m.group("mon"), int(m.group("day")), m.group("hms"), int(m.group("year"))
            out = self.t(dt.datetime(year, MON[mon], day, *map(int, hms.split(":")), tzinfo=dt.timezone.utc))
            wd = (DAY[out.weekday()] + " ") if m.group("wd") else ""
            # openssl pads a one-digit day with a space ("Jun  4"); keep the source's width
            pad = f"{out.day:2d}" if m.group("day").startswith(" ") else str(out.day)
            return f"{wd}{calendar.month_abbr[out.month]} {pad} {out:%H:%M:%S} {out.year}{m.group('gmt') or ''}"
        s = re.sub(r"(?P<wd>\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) )?\b(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
                   r"(?P<day>[ \d]?\d) (?P<hms>\d{2}:\d{2}:\d{2}) (?P<year>\d{4})(?P<gmt> GMT)?", ctime, s)

        def gtime(m):  # LDAP generalised time 20261124183358Z, and the same digits bare in a name
            try:  # (idlab-signing-20261125171352, a key the lab named after when it made it)
                base = dt.datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc)
            except ValueError:
                return m.group(0)
            out = self.t(base)
            return f"{out:%Y%m%d%H%M%S}{m.group(2) or ''}{m.group(3) or ''}"
        s = re.sub(r"(?<!\d)(20\d{12})(\.\d+)?(Z)?(?!\d)", gtime, s)

        def hexepoch(m):  # slapd: 6b05e6d8.3785d1dd at the start of a line
            v = int(m.group(1), 16)
            if not LO <= v <= HI:
                return m.group(0)
            self.n += 1
            return f"{v + int(round(self.delta)):08x}.{m.group(2)}"
        s = re.sub(r"(?<![0-9a-f])([0-9a-f]{8})\.([0-9a-f]{8})(?![0-9a-f])", hexepoch, s)

        def epoch(m):
            v = m.group(1)
            n = int(v)
            if len(v) == 13 and LO * 1000 <= n <= HI * 1000:
                self.n += 1
                return str(n + int(round(self.delta * 1000))) + (m.group(2) or "")
            if len(v) == 10 and LO <= n <= HI:
                self.n += 1
                return str(n + int(round(self.delta))) + (m.group(2) or "")
            return m.group(0)
        s = re.sub(r"(?<![\w.-])(\d{13}|\d{10})(\.\d+)?(?![\w-])", epoch, s)

        def dateonly(m):
            out = dt.date.fromisoformat(m.group(1)) + dt.timedelta(days=self.days)
            self.n += 1
            return out.isoformat()
        s = re.sub(r"(?<![\d-])(\d{4}-\d{2}-\d{2})(?![\dT:-]| \d{2}:)", dateonly, s)
        return s


def raw_date_tokens(t):
    """How the capture's own days would look, to prove none survived."""
    toks = set()
    for d in (t - dt.timedelta(days=1), t, t + dt.timedelta(days=1)):
        toks |= {f"{d:%Y-%m-%d}", f"{d:%Y/%m/%d}", f"{d:%d/%b/%Y}", f"{d:%Y%m%d}", f"{calendar.month_abbr[d.month]} {d.day:2d} ",
                 f"{calendar.month_abbr[d.month]} {d.day} "}
    toks.add(str(int(t.timestamp()))[:5])
    toks.add(f"{int(t.timestamp()):08x}"[:4])
    return toks


# --- reading the raw capture ----------------------------------------------------------
def read(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return default


def lines_of(path):
    return [ln.rstrip("\n") for ln in read(path).splitlines()]


NOISE = re.compile(r"/healthz|/nginx-healthz|Python-urllib|idlab-status|\"curl/|user-session-purge-expired|"
                   r"/resources/[^ ]*\.(css|js|woff2?|svg|png|ico)|realmName=\"master\"")


def ldap_noise(lines):
    """Drop slapd's lines for the health check's own connections: those from
    127.0.0.1, and those that ask WHOAMI (the health check is ldapwhoami)."""
    local = set()
    for ln in lines:
        m = re.search(r"conn=(\d+) fd=\d+ ACCEPT from IP=127\.0\.0\.1:", ln) or re.search(r"conn=(\d+) op=\d+ WHOAMI", ln)
        if m:
            local.add(m.group(1))
    return [ln for ln in lines if not any(re.search(rf"conn={c}\b", ln) for c in local)]


def cap(tool, lines, n):
    """At most n lines: every warning and error first (up to n), then the latest
    others, kept in their original order."""
    if len(lines) <= n:
        return lines, 0
    sev = [severity(tool, ln) for ln in lines]
    keep = [i for i, s in enumerate(sev) if s != "normal"][-n:]
    rest = [i for i, s in enumerate(sev) if s == "normal"]
    keep = sorted(set(keep) | set(rest[len(rest) - (n - len(keep)):] if n > len(keep) else []))
    return [lines[i] for i in keep], len(lines) - len(keep)


class Text(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.out, self.title, self.skip, self.in_title = [], "", 0, False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        if tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip -= 1
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data.strip()
        elif not self.skip and data.strip():
            self.out.append(re.sub(r"\s+", " ", data.strip()))


def user_report(raw):
    meta = raw["meta"]
    if meta["app"] == "radius":
        return [ln for ln in lines_of(f"{raw['dir']}/login.out") if ln.startswith("nas:")]
    page = read(f"{raw['dir']}/page.html")
    if not page:
        return ["(the browser showed no page)"]
    p = Text()
    p.feed(page)
    out = [f"Page title: {p.title or '(none)'}"] + p.out
    # Stop at the debug page's token dumps: the token inspector has those.
    for i, ln in enumerate(out):
        if ln.startswith(("Timing", "ID token header")):
            out = out[:i]
            break
    return out[:25]


def har_summary(raw):
    try:
        har = json.loads(read(f"{raw['dir']}/browser.har"))
    except ValueError:
        return [NO_BROWSER]
    out = []
    for e in har["log"]["entries"]:
        url = e["request"]["url"]
        if re.search(r"/resources/|\.(css|js|woff2?|svg|png|ico)(\?|$)|favicon", url):
            continue
        r = e["response"]
        line = f"{e['startedDateTime']} {e['request']['method']} {url} -> {r['status']}"
        if r.get("redirectURL"):
            line += f" redirect {r['redirectURL']}"
        out.append(line)
        for h in r.get("headers", []):
            if h["name"].lower() == "set-cookie":
                for v in h["value"].split("\n"):
                    out.append("    Set-Cookie: " + v)
    return out


def cookie_summary(raw):
    try:
        j = json.loads(read(f"{raw['dir']}/browser-cookies.json"))
    except ValueError:
        return [NO_BROWSER]
    out = []
    for s in j.get("steps", []):
        out.append(f"{s['step']} at {s['url']}:")
        for c in s.get("cookies", []):
            flags = [f for f in ("secure", "httpOnly") if c.get(f)]
            out.append(f"    {c['name']} domain={c.get('domain')} path={c.get('path')} "
                       f"{' '.join(flags) or 'no flags'} SameSite={c.get('sameSite')}")
        for c in s.get("inferredRefused", []):
            out.append(f"    set but missing from the jar: {c['name']} (set by {c.get('setBy')})")
    for c in j.get("refusedByBrowser", []):
        reasons = " ".join((c.get("reasons") or []) + (c.get("exclusionReasons") or []))
        out.append(f"refused by the browser: {c.get('name')} {reasons}")
    return out


def console(raw):
    if raw["meta"]["app"] == "radius":
        return [NO_BROWSER]
    got = lines_of(f"{raw['dir']}/browser-console.txt")
    return got or ["(the console is empty)"]


def logs(raw, svc):
    lines = [re.sub(r"^(\S+?)\.(\d{3})\d*Z ", r"\1.\2Z ", ln) for ln in lines_of(f"{raw['dir']}/logs/{svc}.log")]
    lines = [ln for ln in lines if not NOISE.search(ln)]
    if svc == "ldap":
        lines = ldap_noise(lines)
    return lines or ["(nothing logged in this window)"]


def kc_events(raw):
    return [ln for ln in logs(raw, "keycloak") if "org.keycloak.events" in ln] or ["(no events in this window)"]


def changes(raw):
    """A change record: what differs between the snapshots taken before and
    after, and the admin events in the window. Comments were dropped when the
    snapshots were taken."""
    before, after = f"{raw['dir']}/before", f"{raw['dir']}/after"
    names = sorted(set(os.listdir(before)) | set(os.listdir(after))) if os.path.isdir(before) else []
    out, n = [], 0
    for name in names:
        a, b = lines_of(f"{before}/{name}"), lines_of(f"{after}/{name}")
        if a == b:
            continue
        n += 1
        out.append(f"Changed: {name.replace('__', '/')}")
        for d in difflib.unified_diff(a, b, lineterm="", n=0):
            if d.startswith(("---", "+++", "@@")):
                continue
            out.append(("- " if d[0] == "-" else "+ ") + d[1:])
    admin = lines_of(f"{raw['dir']}/admin-events.txt")
    head = [f"Change record, {raw['meta']['since']} to {raw['meta']['end']}: "
            f"{n} configuration change(s), {len(admin)} admin event(s)"]
    if not n:
        head.append("No configuration changes recorded in this window.")
    return head + out + admin


def tool_lines(raw, tool):
    d = raw["dir"]
    if tool == "user-report":
        return user_report(raw)
    if tool == "compose-ps":
        return lines_of(f"{d}/ps.txt")
    if tool == "keycloak-events":
        return kc_events(raw)
    if tool.startswith("logs-"):
        return logs(raw, tool[5:])
    if tool == "browser-har":
        return har_summary(raw)
    if tool == "browser-cookies":
        return cookie_summary(raw)
    if tool == "browser-console":
        return console(raw)
    if tool == "recent-changes":
        return changes(raw)
    if tool == "token":
        got = lines_of(f"{d}/token.txt")
        return got if got and got != ["NO_TOKEN"] else [NO_TOKEN]
    # radius-test, clock, trusted-keys, ldap-user: written by the capture script
    return lines_of(f"{d}/{tool}.txt") or ["(no output)"]


def make_common(raw_dir, common_dir):
    """The placeholder map, from what the capture saved: docker inspect of every
    container, the compose file's services and networks, Keycloak's users,
    clients, components and realm ID, and the host's own names (env.json)."""
    env = json.loads(read(f"{common_dir}/env.json"))
    compose = json.loads(read(f"{common_dir}/compose.json"))
    inspect = json.loads(read(f"{raw_dir}/inspect.json", "[]"))
    project = env["project"]
    pairs, nets = [], set()
    for svc, conf in sorted(compose.get("services", {}).items()):
        # a service with network_mode (host, none) has no address of its own
        for net in sorted((conf.get("networks") or {}).keys() or ([] if conf.get("network_mode") else ["default"])):
            pairs.append((svc, net))
            nets.add(net)
    nets = sorted(nets)
    ips, containers = {}, {}
    for c in inspect:
        labels = c.get("Config", {}).get("Labels", {}) or {}
        svc = labels.get("com.docker.compose.service")
        if not svc:
            continue
        containers[c["Id"]] = svc
        containers[c["Id"][:12]] = svc
        containers[c.get("Name", "").lstrip("/")] = svc
        for full, n in (c.get("NetworkSettings", {}).get("Networks") or {}).items():
            net = full[len(project) + 1:] if full.startswith(project + "_") else full
            if n.get("IPAddress") and (svc, net) in pairs:
                ips[n["IPAddress"]] = f"192.0.2.{10 + pairs.index((svc, net))}"
            if n.get("Gateway") and net in nets:
                ips[n["Gateway"]] = f"198.51.100.{1 + nets.index(net)}"
    fixed = {}
    kc = json.loads(read(f"{raw_dir}/keycloak-ids.json", "{}"))
    for u in kc.get("users", []):
        fixed[u["id"]] = f"<user:{u['username']}>"
    for c in kc.get("clients", []):
        fixed[c["id"]] = f"<client:{c['clientId']}>"
    for c in kc.get("components", []):
        fixed[c["id"]] = f"<component:{c['name']}>"
    if kc.get("realm"):
        fixed[kc["realm"]] = "<realm:idlab>"
    # The host's own addresses (the LAN's, as Node's TLS proxy reaches the lab
    # through real DNS): fixed placeholders, the same in every pack.
    for i, a in enumerate(env.get("host_ips", [])):
        ips.setdefault(a, f"198.51.100.{250 + i}")
    # longest first, so a container's full ID goes before its 12-character prefix
    containers = dict(sorted(containers.items(), key=lambda kv: -len(kv[0])))
    return {"fixed": fixed, "containers": containers, "ips": ips,
            "unknown_ips": json.loads(read(f"{common_dir}/unknown-ips.json", "{}")), "lab_host": env["lab_host"],
            "lab_root": env["lab_root"], "home": env.get("home"), "hostname": env.get("hostname")}


def build(raw_dir, common_dir, out_path):
    meta = json.loads(read(f"{raw_dir}/meta.json"))
    common = make_common(raw_dir, common_dir)
    secrets = [v for v in read(f"{common_dir}/secrets").split("\n") if v]
    seen = [v for v in read(f"{common_dir}/seen/cookie-values").split("\n") if len(v) >= 8]
    raw = {"dir": raw_dir, "meta": meta}
    login = dt.datetime.fromtimestamp(meta["login_at"], dt.timezone.utc)
    delta = (ANCHOR - login).total_seconds()
    days = (ANCHOR.date() - login.date()).days
    shifter = Shifter(delta, days)
    ph = Placeholders(common, {})
    commands = json.loads(read(f"{raw_dir}/commands.json", "{}"))
    tools = []
    for tool, title in TOOLS:
        lines = tool_lines(raw, tool)
        lines = [shifter.shift(ph.apply(scrub_secrets(ln, secrets + seen))) for ln in lines]
        n = CAP_LOG if tool.startswith("logs-") or tool == "keycloak-events" else 60 if tool == "token" else CAP
        kept, omitted = cap(tool, lines, n)
        tools.append({"tool": tool, "title": title,
                      "command": shifter.shift(ph.apply(scrub_secrets(commands.get(tool, ""), secrets))),
                      "lines": [{"text": ln, "severity": severity(tool, ln)} for ln in kept],
                      "omitted": omitted})
    pack = {"format": FORMAT, "id": meta["id"], "login_at": ANCHOR.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "captured": shifter.shift(dt.datetime.fromtimestamp(meta["end_at"], dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
            "lab": {"host": "lab.example"}, "tools": tools}
    text = json.dumps(pack, indent=1, ensure_ascii=False)
    problems = []
    for v in secrets + seen:
        if v in text:
            problems.append("a secret or cookie value")
            break
    if JWT_RE.search(text) or PEM_RE.search(text):
        problems.append("a token or PEM block")
    left = [t for t in raw_date_tokens(login) if t in text]
    if left:
        problems.append(f"{len(left)} unshifted date form(s)")
    if common.get("unknown_new"):
        # one map for the whole build, so 203.0.113.N means the same address in every pack
        with open(f"{common_dir}/unknown-ips.json", "w") as fh:
            json.dump(common["unknown_ips"], fh)
    if common["unknown_ips"]:
        print(f"note: {len(common['unknown_ips'])} address(es) from neither a container nor the host became 203.0.113.N", file=sys.stderr)
    if problems:
        print(f"pack {meta['id']} not written: {', '.join(problems)}", file=sys.stderr)
        return 1
    with open(out_path, "w") as fh:
        fh.write(text + "\n")
    print(f"pack {meta['id']}: {sum(len(t['lines']) for t in tools)} lines, {shifter.n} timestamps shifted")
    return 0


# --- checks for scripts/test.sh -----------------------------------------------------------
def load(d):
    out = {}
    for f in sorted(os.listdir(d)):
        if f.endswith(".json"):
            with open(os.path.join(d, f)) as fh:
                out[f[:-5]] = json.load(fh)
    return out


def validate(packs_dir, answers_dir):
    packs, answers = load(packs_dir), load(answers_dir)
    bad = []
    want = [t for t, _ in TOOLS]
    for name, p in packs.items():
        if p.get("format") != FORMAT or p.get("id") != name:
            bad.append(f"{name}: format or id")
        if [t["tool"] for t in p.get("tools", [])] != want:
            bad.append(f"{name}: tools are not the {len(want)} expected, in order")
        for t in p.get("tools", []):
            for ln in t["lines"]:
                if ln.get("severity") not in SEVERITIES or not isinstance(ln.get("text"), str):
                    bad.append(f"{name}: {t['tool']}: a line without text or a valid severity")
                    break
        if p.get("login_at") != ANCHOR.strftime("%Y-%m-%dT%H:%M:%SZ"):
            bad.append(f"{name}: login_at is not the anchor")
        if name != "healthy" and name not in answers:
            bad.append(f"{name}: no answer key")
    for name, a in answers.items():
        if name not in packs or a.get("id") != name or not all(a.get(k) for k in ("scenario", "runbook", "fix")):
            bad.append(f"answer {name}: no pack, or missing id, scenario, runbook or fix")
    print(f"{len(packs)} pack(s), {len(answers)} answer key(s): {len(bad)} problem(s)")
    for b in bad:
        print("  " + b)
    return 1 if bad or not packs else 0


def _when(s):
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


CLOCK_RE = re.compile(r"^(?P<svc>[\w-]+) +(?P<t>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) +host (?P<h>\S+) +offset (?P<o>[+-]\d+) s")
CERT_RE = re.compile(r"^(?P<what>.+?) notAfter=(?P<t>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) \((?P<rel>expired|valid)")


def check_time(packs_dir, answers_dir):
    """The relationships normalisation must keep: each clock line's offset,
    recomputed from its shifted times, equals the offset the capture recorded
    from the raw times; and each certificate marked expired (or valid) at the
    login is expired (or valid) relative to the shifted login time."""
    packs, answers = load(packs_dir), load(answers_dir)
    by_scenario = {a["scenario"]: name for name, a in answers.items()}
    anchor = ANCHOR
    bad, seen = [], {}
    for name, p in packs.items():
        tools = {t["tool"]: [ln["text"] for ln in t["lines"]] for t in p["tools"]}
        for ln in tools["clock"]:
            m = CLOCK_RE.match(ln)
            if m:
                got = int((_when(m.group("t")) - _when(m.group("h"))).total_seconds())
                if got != int(m.group("o")):
                    bad.append(f"{name}: {m.group('svc')} offset {got} s after shifting, {m.group('o')} s observed")
                seen.setdefault(name, {})[m.group("svc")] = got
        for ln in tools["trusted-keys"] + tools["token"]:
            m = CERT_RE.match(ln)
            if m:
                expired = _when(m.group("t")) <= anchor
                if expired != (m.group("rel") == "expired"):
                    bad.append(f"{name}: {m.group('what')} is {m.group('rel')} at the login, but not after shifting")
                seen.setdefault(name, {}).setdefault("certs", []).append((m.group("what"), m.group("rel")))
    def need(scn, test, what):
        n = by_scenario.get(scn)
        if not n:
            bad.append(f"no pack for {scn}")
        elif not test(seen.get(n, {}), packs[n]):
            bad.append(f"{scn} ({n}): {what}")
        else:
            print(f"{scn} ({n}): {what}: kept")
    need("clock-skew", lambda s, p: abs(s.get("saml-sp", 0) - 600) <= 5, "the SAML app's clock about +600 s from the host")
    need("totp-clock-drift", lambda s, p: abs(s.get("authenticator", 0)) >= 60, "the authenticator's clock a minute or more out")
    need("expired-signing-cert", lambda s, p: any(r == "expired" for w, r in s.get("certs", []) if "signing" in w.lower() or "idp" in w.lower()),
         "an IdP signing certificate expired before the login")
    need("client-cert-expired", lambda s, p: any(r == "expired" for w, r in s.get("certs", []) if "client" in w.lower()),
         "the partner client certificate expired before the login")
    need("client-cert-missing", lambda s, p: any("no client certificate" in ln["text"] for t in p["tools"] if t["tool"] == "trusted-keys" for ln in t["lines"]),
         "the partner system has no client certificate")
    # Every timestamp in a log (each line's Docker time, and the service's own in
    # any format the shifter knows) must be within a day of the login.
    stamp = re.compile(r"\b(\d{4})[-/](\d{2})[-/](\d{2})[T ]\d{2}:\d{2}:\d{2}")
    for name, p in packs.items():
        for t in p["tools"]:
            if not (t["tool"].startswith("logs-") or t["tool"] == "keycloak-events"):
                continue
            for ln in t["lines"]:
                for y, mo, d in stamp.findall(ln["text"]):
                    when = dt.datetime(int(y), int(mo), int(d), tzinfo=dt.timezone.utc)
                    if abs((when - anchor.replace(hour=0, minute=0, second=0)).days) > 1:
                        bad.append(f"{name}: {t['tool']}: a timestamp not within a day of the login: {y}-{mo}-{d}")
                        break
    need_h = seen.get("healthy", {})
    if any(r == "expired" for _, r in need_h.get("certs", [])) or any(abs(v) > 5 for k, v in need_h.items() if k != "certs"):
        bad.append("healthy: a certificate expired or a clock off")
    else:
        print("healthy: every clock within 5 s, every certificate valid at the login: kept")
    print(f"time relationships: {len(bad)} problem(s)")
    for b in bad:
        print("  " + b)
    return 1 if bad else 0


def selftest():
    """The shifter on made-up lines: every format moves by the same delta."""
    login = dt.datetime(2026, 11, 24, 18, 33, 58, tzinfo=dt.timezone.utc)
    sh = Shifter((ANCHOR - login).total_seconds(), (ANCHOR.date() - login.date()).days)
    cases = {
        "2026-11-24T18:33:58.123Z x": "2026-06-14T02:14:00.123Z x",
        "2026-11-24 18:33:58,196 WARN": "2026-06-14 02:14:00,196 WARN",
        "[24/Nov/2026:18:33:58 +0000]": "[14/Jun/2026:02:14:00 +0000]",
        "Tue Nov 24 18:33:58 2026 : Auth": "Sun Jun 14 02:14:00 2026 : Auth",
        "notAfter=Nov 24 18:33:58 2026 GMT": "notAfter=Jun 14 02:14:00 2026 GMT",
        "1795545238.574 12 TCP": f"{1795545238 + int(round(sh.delta))}.574 12 TCP",
        '"exp": 1795545238,': f'"exp": {1795545238 + int(round(sh.delta))},',
        "start 1795545238000": f"start {1795545238000 + int(round(sh.delta * 1000))}",
        "6b05e6d8.3785d1dd 0x7 conn=1": f"{0x6b05e6d8 + int(round(sh.delta)):08x}.3785d1dd 0x7 conn=1",
        "modifyTimestamp: 20261124183358Z": "modifyTimestamp: 20260614021400Z",
        "Local time: Tue 2026-11-24 18:33:58 UTC": "Local time: Sun 2026-06-14 02:14:00 UTC",
        "expired on 2026-11-23": "expired on 2026-06-13",
        "2026/11/24 18:33:58 [info] 1437#1437": "2026/06/14 02:14:00 [info] 1437#1437",
        "2026/11/24 18:33:58| Adding nameserver": "2026/06/14 02:14:00| Adding nameserver",
        "certificate expired on Tue Nov 24 18:33:58 GMT 2026)": "certificate expired on Sun Jun 14 02:14:00 GMT 2026)",
        "idlab-signing-20261124183358 (rsa)": "idlab-signing-20260614021400 (rsa)",
        "port 20261399999999 no": "port 20261399999999 no",
        "notAfter=Nov  4 18:33:58 2026 GMT": "notAfter=May 25 02:14:00 2026 GMT",
        "port 8180 pid 12345 id 1234567": "port 8180 pid 12345 id 1234567",
    }
    bad = [(i, sh.shift(i), o) for i, o in cases.items() if sh.shift(i) != o]
    for i, got, want in bad:
        print(f"  {i!r}: got {got!r}, want {want!r}")
    print(f"shifter self-test: {len(cases)} cases, {len(bad)} wrong")
    return 1 if bad else 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "build" and len(sys.argv) == 5:
        return build(*sys.argv[2:])
    if cmd == "validate" and len(sys.argv) == 4:
        return validate(*sys.argv[2:])
    if cmd == "check-time" and len(sys.argv) == 4:
        return check_time(*sys.argv[2:])
    if cmd == "selftest":
        return selftest()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
