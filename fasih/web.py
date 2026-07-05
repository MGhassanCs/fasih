"""`fasih serve` -- a small local dashboard for fasih.

Runs the real scanner and renders findings in the browser, with a short
explainer and a rules reference so someone new can understand what fasih does
and try it in a few clicks. Standard library only (no extra dependency), and
bound to 127.0.0.1 by default so it stays on the local machine.
"""

from __future__ import annotations

import html
import os
import secrets
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import fasih
from fasih.findings import Severity
from fasih.rules_engine import scan

_PKG_DIR = os.path.dirname(fasih.__file__)
_REPO_DIR = os.path.dirname(_PKG_DIR)
_EXAMPLE = os.path.join(_REPO_DIR, "examples", "broken_agent_example.py")
_HOME = os.path.expanduser("~")
_DESKTOP = os.path.join(_HOME, "Desktop")
_START_DIR = _DESKTOP if os.path.isdir(_DESKTOP) else _HOME

_SEV = {
    Severity.CRITICAL: ("CRITICAL", "crit"),
    Severity.HIGH: ("HIGH", "high"),
    Severity.MEDIUM: ("MEDIUM", "med"),
    Severity.LOW: ("LOW", "low"),
}

# (rule id, group, one-line description) -- powers the reference section.
_RULES = [
    ("FAIL-OPEN-GUARD", "core", "A safety/guardrail call wrapped in try/except that swallows the error and continues -- fails open."),
    ("ORPHANED-TOOL", "core", "A tool/fetcher defined but never invoked or registered anywhere in the project."),
    ("STRUCTURE-NOT-SEMANTICS", "core", "An eval that checks response shape (keys/length) but never whether the content is correct."),
    ("HARDCODED-SECRET", "core", "Provider API keys, private-key blocks, or secret-named literals committed in source."),
    ("AR-ENCODING", "ar", "json.dumps without ensure_ascii=False -- escapes Arabic to \\uXXXX in payloads and files."),
    ("AR-NUMERAL", "ar", "int()/float() on user text without normalizing Arabic numerals and the Arabic separators."),
    ("AR-NORMALIZE", "ar", "Matching Arabic with ==/in/startswith without normalizing alef/ya/ta-marbuta/tatweel/diacritics."),
    ("AR-FILE-ENCODING", "ar", "open()/write_text() without encoding='utf-8' -- Arabic then breaks by machine locale."),
    ("AR-ENCODE-ASCII", "ar", "text.encode('ascii'/'latin-1') -- cannot represent Arabic, raises UnicodeEncodeError."),
]

_STYLE = """
:root{--bg:#0f1216;--panel:#171b21;--panel2:#1d222a;--text:#e6e9ef;--dim:#9aa4b2;
--line:#2a313b;--accent:#5eb0ef;--crit:#ff5c6c;--high:#ff8a3d;--med:#f2c94c;--low:#5eb0ef;--ok:#4bd884;--ar:#a78bfa}
@media (prefers-color-scheme:light){:root{--bg:#f6f7f9;--panel:#fff;--panel2:#f0f2f5;--text:#161a1f;
--dim:#5b6673;--line:#e2e6ec;--accent:#2563eb;--ar:#7c3aed}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:940px;margin:0 auto;padding:30px 20px 70px}
header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
h1{font-size:32px;margin:0;letter-spacing:-.5px}
h1 .ar{color:var(--accent)}
.tag{color:var(--dim);font-size:14px}
.lead{color:var(--dim);margin:14px 0 4px;max-width:70ch}
.lead b{color:var(--text);font-weight:600}
form{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:20px 0 8px;padding:14px;
background:var(--panel);border:1px solid var(--line);border-radius:12px}
input[type=text]{flex:1;min-width:240px;padding:9px 12px;border-radius:8px;border:1px solid var(--line);
background:var(--panel2);color:var(--text);font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
label.chk{color:var(--dim);font-size:14px;display:flex;align-items:center;gap:6px;cursor:pointer}
button{padding:9px 18px;border-radius:8px;border:0;background:var(--accent);color:#fff;font-weight:600;cursor:pointer}
.quick{margin:6px 0 20px;display:flex;gap:8px;flex-wrap:wrap}
.quick a{font-size:12.5px;color:var(--dim);text-decoration:none;padding:5px 11px;border:1px solid var(--line);border-radius:999px}
.quick a:hover{color:var(--text);border-color:var(--accent)}
.quick a.browse{color:var(--text);border-color:var(--accent)}
.browser{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:6px 0 18px}
.crumbs{font:12.5px ui-monospace,Menlo,monospace;color:var(--dim);margin-bottom:12px;word-break:break-all}
.crumbs a{color:var(--accent);text-decoration:none}
.scanrow{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.scanbtn{background:var(--accent);color:#fff;font-weight:600;padding:8px 14px;border-radius:8px;text-decoration:none;font-size:14px}
.pyhint{font-size:12.5px;color:var(--dim)}.pyhint.ok{color:var(--ok)}
.dirs{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:6px}
.dir{color:var(--text);text-decoration:none;padding:7px 10px;border:1px solid var(--line);border-radius:8px;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dir:hover{border-color:var(--accent)}
.dir.up{color:var(--dim)}
.summary{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 18px;align-items:center}
.chip{font-size:12.5px;padding:4px 11px;border-radius:999px;background:var(--panel2);border:1px solid var(--line);color:var(--dim)}
.chip b{color:var(--text)}
.chip.crit{color:var(--crit);border-color:var(--crit)}.chip.high{color:var(--high);border-color:var(--high)}
.chip.med{color:var(--med);border-color:var(--med)}
.card{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:12px;padding:15px 18px;margin:11px 0}
.card.crit{border-left-color:var(--crit)}.card.high{border-left-color:var(--high)}
.card.med{border-left-color:var(--med)}.card.low{border-left-color:var(--low)}
.row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.badge{font-size:11px;font-weight:700;letter-spacing:.6px;padding:2px 8px;border-radius:6px;color:#0c0e11}
.badge.crit{background:var(--crit)}.badge.high{background:var(--high)}.badge.med{background:var(--med)}.badge.low{background:var(--low)}
.rule{font-weight:700}
.loc{color:var(--accent);font:12.5px ui-monospace,Menlo,monospace;margin-left:auto}
.msg{margin:9px 0 0}
pre{margin:9px 0 0;padding:10px 12px;background:var(--panel2);border-radius:8px;overflow-x:auto;font:12.5px ui-monospace,Menlo,monospace}
.meta{margin-top:9px;font-size:13.5px;color:var(--dim)}.meta b{color:var(--text);font-weight:600}
.fixbadge{margin-top:9px;font-size:12.5px;color:var(--ok);font-weight:600}
.fixbadge code{background:var(--panel2);padding:1px 6px;border-radius:5px}
.ok{text-align:center;padding:40px;border:1px solid var(--ok);border-radius:12px;color:var(--ok);font-size:18px;font-weight:600;background:var(--panel)}
.empty{color:var(--dim);padding:22px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);margin:34px 0 12px}
.ref{display:grid;gap:8px}
.refrow{display:grid;grid-template-columns:190px 1fr;gap:12px;padding:10px 12px;background:var(--panel);border:1px solid var(--line);border-radius:10px;font-size:13.5px}
.refrow code{color:var(--text);font:12.5px ui-monospace,Menlo,monospace}
.refrow.ar code{color:var(--ar)}
.refrow .d{color:var(--dim)}
@media(max-width:560px){.refrow{grid-template-columns:1fr}}
footer{margin-top:36px;color:var(--dim);font-size:13px}
footer a{color:var(--accent);text-decoration:none}
"""


def _render_finding(f):
    label, cls = _SEV[f.severity]
    snippet = ""
    if f.snippet and f.snippet != "<redacted>":
        snippet = "<pre>%s</pre>" % html.escape(f.snippet)
    meta = ""
    if f.why:
        meta += '<div class="meta"><b>Why:</b> %s</div>' % html.escape(f.why)
    if f.fix:
        meta += '<div class="meta"><b>Fix:</b> %s</div>' % html.escape(f.fix)
    if getattr(f, "fixable", False):
        meta += ('<div class="fixbadge">&#9889; auto-fixable &mdash; '
                 'run <code>fasih scan &lt;path&gt; --fix</code></div>')
    return (
        '<div class="card %s"><div class="row">'
        '<span class="badge %s">%s</span><span class="rule">%s</span>'
        '<span class="loc">%s</span></div><div class="msg">%s</div>%s%s</div>'
    ) % (
        cls, cls, label, html.escape(f.rule_id),
        html.escape(os.path.basename(f.file) + ":" + str(f.line)),
        html.escape(f.message), snippet, meta,
    )


def _reference():
    rows = []
    for rule_id, group, desc in _RULES:
        cls = "refrow ar" if group == "ar" else "refrow"
        rows.append('<div class="%s"><code>%s</code><span class="d">%s</span></div>'
                    % (cls, html.escape(rule_id), html.escape(desc)))
    return '<h2>What it checks</h2><div class="ref">%s</div>' % "".join(rows)


def _expand(path):
    """Resolve ~ and env vars and trim whitespace, so a pasted `~/Desktop/x`
    (which Python would NOT expand on its own) works."""
    if not isinstance(path, str):
        return path
    return os.path.expanduser(os.path.expandvars(path.strip()))


def _render(input_value, arabic, token, chips, body):
    return _TEMPLATE % {
        "style": _STYLE,
        "path": html.escape(input_value),
        "checked": "checked" if arabic else "",
        "ex": urllib.parse.quote(_EXAMPLE),
        "pkg": urllib.parse.quote(_PKG_DIR),
        "start": urllib.parse.quote(_START_DIR),
        "chips": chips,
        "body": body,
        "reference": _reference(),
        "ver": html.escape(fasih.__version__),
        "token": urllib.parse.quote(token),
    }


def render_page(path, arabic, token=""):
    expanded = _expand(path)
    result = scan(expanded, enable_arabic=arabic)
    counts = result.counts()

    chips = ['<span class="chip"><b>%d</b> file(s)</span>' % result.files_scanned,
             '<span class="chip"><b>%d</b> finding(s)</span>' % len(result.findings)]
    for sev, cls in ((Severity.CRITICAL, "crit"), (Severity.HIGH, "high"), (Severity.MEDIUM, "med")):
        if counts[sev]:
            chips.append('<span class="chip %s"><b>%d</b> %s</span>' % (cls, counts[sev], sev.value))

    if isinstance(expanded, str) and not os.path.exists(expanded):
        body = ('<div class="empty">Path not found: <code>%s</code>.<br>'
                'Paste a full path, or use <b>Browse folders</b> above.</div>' % html.escape(expanded))
    elif result.files_scanned == 0:
        body = ('<div class="empty">That folder has no <code>.py</code> files &mdash; fasih lints '
                '<b>Python</b> (JS/TS is on the roadmap). Use <b>Browse folders</b> to find a Python '
                'project, or try the example below.</div>')
    elif not result.findings:
        body = '<div class="ok">No issues found &#10003;</div>'
    else:
        body = "".join(_render_finding(f) for f in result.findings)

    return _render(path, arabic, token, "".join(chips), body)


def render_browse_page(current, arabic, token=""):
    current = os.path.abspath(_expand(current) or _START_DIR)
    chips = '<span class="chip">&#128193; browsing folders &mdash; open one, then <b>Scan this folder</b></span>'
    return _render(current, arabic, token, chips, _render_browser(current, arabic, token))


def _browse_link(target, arabic, token):
    return "/?browse=%s&amp;arabic=%s&amp;token=%s" % (
        urllib.parse.quote(target), "1" if arabic else "0", urllib.parse.quote(token))


def _render_browser(current, arabic, token):
    # breadcrumbs from filesystem root to current
    crumbs = ['<a href="%s">/</a>' % _browse_link(os.path.sep, arabic, token)]
    accum = ""
    for piece in [p for p in current.split(os.path.sep) if p]:
        accum = accum + os.path.sep + piece
        crumbs.append('<a href="%s">%s</a>' % (_browse_link(accum, arabic, token), html.escape(piece)))

    scan_btn = ('<a class="scanbtn" href="/?path=%s&amp;arabic=1&amp;token=%s">&#8681; Scan this folder</a>'
                % (urllib.parse.quote(current), urllib.parse.quote(token)))

    try:
        entries = sorted(os.listdir(current), key=str.lower)
    except OSError as exc:
        return '<div class="browser"><div class="crumbs">%s</div><div class="empty">Cannot open this folder: %s</div></div>' % (
            " / ".join(crumbs), html.escape(str(exc)))

    subdirs = [d for d in entries if not d.startswith(".") and os.path.isdir(os.path.join(current, d))]
    has_py = any(e.endswith(".py") for e in entries)
    hint = ('<span class="pyhint ok">contains .py &mdash; scannable</span>' if has_py
            else '<span class="pyhint">no .py directly here (may be in sub-folders)</span>')

    rows = []
    parent = os.path.dirname(current)
    if parent and parent != current:
        rows.append('<a class="dir up" href="%s">&#8598; ..</a>' % _browse_link(parent, arabic, token))
    for d in subdirs:
        rows.append('<a class="dir" href="%s">&#128193; %s</a>'
                    % (_browse_link(os.path.join(current, d), arabic, token), html.escape(d)))
    listing = "".join(rows) if rows else '<div class="empty">no sub-folders here</div>'

    return ('<div class="browser"><div class="crumbs">%s</div>'
            '<div class="scanrow">%s %s</div><div class="dirs">%s</div></div>') % (
        " / ".join(crumbs), scan_btn, hint, listing)


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fasih dashboard</title><style>%(style)s</style></head><body><div class="wrap">
<header><h1>fasih <span class="ar">&#1601;&#1589;&#1610;&#1581;</span></h1>
<span class="tag">a linter for AI agents &amp; Arabic/bilingual pipelines</span></header>
<p class="lead">fasih reads your Python <b>without running it</b> and flags the bugs a passing
test suite misses: guardrails that fail open, orphaned tools, evals that grade shape instead of
meaning &mdash; plus the <b>Arabic pipeline bugs that only ever break for Arabic users</b>
(encoding, numerals, and text normalization). Point it at a file or folder:</p>
<form method="get" action="/">
<input type="hidden" name="token" value="%(token)s">
<input type="text" name="path" value="%(path)s" placeholder="path to a .py file or a directory">
<label class="chk"><input type="checkbox" name="arabic" value="1" %(checked)s> Arabic checks</label>
<button type="submit">Scan</button></form>
<div class="quick">
<a class="browse" href="/?browse=%(start)s&amp;arabic=1&amp;token=%(token)s">&#128193; Browse folders&hellip;</a>
<a href="/?path=%(ex)s&amp;arabic=1&amp;token=%(token)s">&#9656; the planted-bug example (10 findings)</a>
<a href="/?path=%(pkg)s&amp;arabic=1&amp;token=%(token)s">&#9656; fasih's own source (clean)</a></div>
<div class="summary">%(chips)s</div>
%(body)s
%(reference)s
<footer>fasih v%(ver)s &middot; <a href="https://github.com/MGhassanCs/fasih">github.com/MGhassanCs/fasih</a>
&middot; this dashboard runs the real scanner locally (stdlib only)</footer>
</div></body></html>"""


# Only loopback Host headers are served. This blocks DNS-rebinding: a malicious
# page that rebinds its name to 127.0.0.1 still sends its own hostname as Host,
# which is rejected here; and cross-origin reads are already blocked by the
# same-origin policy (no CORS headers are ever sent).
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# The page is fully self-contained: inline styles, one form, no scripts, no
# external resources. This CSP locks that down and neutralizes injected markup.
_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)


class _Handler(BaseHTTPRequestHandler):
    server_version = "fasih"
    sys_version = ""

    def _host_allowed(self) -> bool:
        host = self.headers.get("Host", "")
        hostname = urllib.parse.urlsplit("//" + host).hostname
        return hostname in _LOOPBACK_HOSTS

    def _is_cross_site(self) -> bool:
        # Reject requests a browser marks as cross-site (blocks a malicious page
        # from driving the dashboard via <img>/fetch to 127.0.0.1).
        site = self.headers.get("Sec-Fetch-Site")
        if site in ("cross-site", "same-site"):
            return True
        origin = self.headers.get("Origin")
        if origin and urllib.parse.urlsplit(origin).hostname not in _LOOPBACK_HOSTS:
            return True
        return False

    def _token_ok(self, query) -> bool:
        # A per-run token (printed by `fasih serve`) is required, so no
        # unauthenticated request — CSRF or remote — can trigger a scan.
        token = getattr(self.server, "fasih_token", None)
        if token is None:
            return True  # not configured (programmatic/test use)
        return secrets.compare_digest(query.get("token", [""])[0], token)

    def _send(self, status: int, body: bytes, content_type="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if not self._host_allowed() or self._is_cross_site():
            self._send(403, b"forbidden", "text/plain")
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/favicon.ico":
            self._send(204, b"")
            return
        if parsed.path != "/":
            self._send(404, b"not found", "text/plain")
            return
        query = urllib.parse.parse_qs(parsed.query)
        if not self._token_ok(query):
            self._send(403, b"forbidden: open the URL printed by 'fasih serve' (missing/invalid token)", "text/plain")
            return
        token = getattr(self.server, "fasih_token", None) or ""
        arabic = query.get("arabic", ["1"])[0] in ("1", "true", "on")
        try:
            if "browse" in query:
                page = render_browse_page(query.get("browse", [_START_DIR])[0], arabic, token)
            else:
                page = render_page(query.get("path", [_EXAMPLE])[0], arabic, token)
        except Exception as exc:  # never let one bad path kill the dashboard
            page = "<pre>error: %s</pre>" % html.escape(repr(exc))
        self._send(200, page.encode("utf-8"))

    def log_message(self, *args):
        pass  # keep the console quiet


def serve(host="127.0.0.1", port=8787):
    if host not in _LOOPBACK_HOSTS:
        print(
            "WARNING: binding to %s exposes the dashboard beyond localhost.\n"
            "It runs read-only static analysis and reveals source snippets of scanned\n"
            "files to anyone who can reach this address. Use 127.0.0.1 unless you are sure." % host
        )
    server = ThreadingHTTPServer((host, port), _Handler)
    server.fasih_token = secrets.token_urlsafe(16)
    url = "http://localhost:%d/?token=%s" % (port, server.fasih_token)
    print("fasih dashboard running at %s" % url, flush=True)
    print("(open that exact URL — it carries a one-time token; Ctrl-C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        server.server_close()
