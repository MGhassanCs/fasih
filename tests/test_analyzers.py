"""Unit tests per analyzer, plus an end-to-end fixture scan and a self-scan
that enforces fasih's zero-false-positive guarantee on its own source."""

import ast
import os

import pytest

from fasih import (
    normalize_arabic,
    normalize_arabic_indic_digits,
    strip_tashkeel,
    strip_tatweel,
)
from fasih.rules_engine import scan
from fasih.analyzers.fail_open import FailOpenAnalyzer
from fasih.analyzers.orphaned_tools import OrphanedToolAnalyzer
from fasih.analyzers.eval_structure import EvalStructureAnalyzer
from fasih.analyzers.secrets import SecretsAnalyzer
from fasih.arabic.encoding_check import ArabicEncodingAnalyzer
from fasih.arabic.numeral_check import ArabicNumeralAnalyzer
from fasih.arabic.normalize_check import ArabicNormalizeAnalyzer
from fasih.arabic.io_check import ArabicTextIoAnalyzer
from fasih.arabic.bidi_check import ArabicBidiAnalyzer
from fasih import wrap_ltr


def ar(*codepoints):
    """Build an Arabic string from code points, so this test file stays ASCII
    and every character is unambiguous."""
    return "".join(chr(c) for c in codepoints)


NAAM = ar(0x0646, 0x0639, 0x0645)  # نعم  ("yes")
LAA = ar(0x0644, 0x0627)  # لا  ("no")

HERE = os.path.dirname(__file__)
EXAMPLE = os.path.join(HERE, "..", "examples", "broken_agent_example.py")


def run(analyzer, source, filename="<test>.py"):
    """Run one analyzer over a source string and return its findings."""
    tree = ast.parse(source)
    findings = list(analyzer.check(tree, filename, source))
    analyzer.collect(tree, filename, source)
    findings += list(analyzer.finalize())
    return findings


def rules(findings):
    return {f.rule_id for f in findings}


# --- FAIL-OPEN-GUARD --------------------------------------------------------

def test_fail_open_flags_fallthrough():
    src = (
        "def h(p):\n"
        "    try:\n"
        "        ok = guardrail_check(p)\n"
        "    except Exception:\n"
        "        ok = True\n"
        "    return ok\n"
    )
    assert "FAIL-OPEN-GUARD" in rules(run(FailOpenAnalyzer(), src))


def test_fail_open_flags_return_true():
    src = (
        "def is_safe(p):\n"
        "    try:\n"
        "        return moderation_check(p)\n"
        "    except Exception:\n"
        "        return True\n"
    )
    assert "FAIL-OPEN-GUARD" in rules(run(FailOpenAnalyzer(), src))


def test_fail_open_ignores_reraise():
    src = (
        "def h(p):\n"
        "    try:\n"
        "        return guardrail_check(p)\n"
        "    except Exception:\n"
        "        raise\n"
    )
    assert rules(run(FailOpenAnalyzer(), src)) == set()


def test_fail_open_ignores_return_deny_value():
    src = (
        "def h(p):\n"
        "    try:\n"
        "        ok = guardrail_check(p)\n"
        "    except Exception:\n"
        "        return 'blocked'\n"
        "    return ok\n"
    )
    assert rules(run(FailOpenAnalyzer(), src)) == set()


def test_fail_open_ignores_non_guardrail_try():
    src = (
        "def h(p):\n"
        "    try:\n"
        "        return compute_total(p)\n"
        "    except Exception:\n"
        "        return None\n"
    )
    assert rules(run(FailOpenAnalyzer(), src)) == set()


# --- ORPHANED-TOOL ----------------------------------------------------------

def test_orphaned_tool_flags_unused():
    src = "@tool\ndef fetch_weather(city):\n    return city\n"
    assert "ORPHANED-TOOL" in rules(run(OrphanedToolAnalyzer(), src))


def test_orphaned_tool_ignores_used():
    src = (
        "@tool\n"
        "def fetch_weather(city):\n"
        "    return city\n"
        "def router(c):\n"
        "    return fetch_weather(c)\n"
    )
    assert rules(run(OrphanedToolAnalyzer(), src)) == set()


def test_orphaned_tool_ignores_string_registered():
    # dispatched dynamically by name string → must not be flagged
    src = (
        "@tool\n"
        "def fetch_weather(city):\n"
        "    return city\n"
        "REGISTRY = ['fetch_weather']\n"
    )
    assert rules(run(OrphanedToolAnalyzer(), src)) == set()


# --- STRUCTURE-NOT-SEMANTICS ------------------------------------------------

def test_eval_structure_flags_shape_only():
    src = (
        "def evaluate(response):\n"
        "    assert isinstance(response, dict)\n"
        "    assert 'answer' in response\n"
        "    assert len(response['answer']) > 0\n"
        "    return True\n"
    )
    assert "STRUCTURE-NOT-SEMANTICS" in rules(run(EvalStructureAnalyzer(), src))


def test_eval_structure_ignores_expected_compare():
    src = (
        "def grade(response, expected_answer):\n"
        "    assert isinstance(response, dict)\n"
        "    return response['answer'].strip() == expected_answer.strip()\n"
    )
    assert rules(run(EvalStructureAnalyzer(), src)) == set()


def test_eval_structure_ignores_long_string_compare():
    src = (
        "def score(out):\n"
        "    return out.strip() == 'the mitochondria is the powerhouse of the cell'\n"
    )
    assert rules(run(EvalStructureAnalyzer(), src)) == set()


# --- HARDCODED-SECRET -------------------------------------------------------

def test_secret_flags_generic_assignment():
    src = "API_TOKEN = 'a1b2c3d4e5f6g7h8i9j0k1'\n"
    assert "HARDCODED-SECRET" in rules(run(SecretsAnalyzer(), src))


def test_secret_ignores_placeholder():
    src = "api_key = 'your-api-key-here'\n"
    assert rules(run(SecretsAnalyzer(), src)) == set()


def test_secret_ignores_env_lookup():
    src = "import os\napi_key = os.environ['OPENAI_API_KEY']\n"
    assert rules(run(SecretsAnalyzer(), src)) == set()


def test_secret_flags_provider_key():
    # assembled at runtime so no contiguous key literal is committed to git
    key = "sk-" + "ant-" + "0123456789abcdef0123456789ABC"
    src = f"client = Anthropic(api_key='{key}')\n"
    findings = run(SecretsAnalyzer(), src)
    assert any(f.rule_id == "HARDCODED-SECRET" and f.severity.value == "critical" for f in findings)


# --- AR-ENCODING ------------------------------------------------------------

def test_ar_encoding_flags_missing_ensure_ascii():
    src = "import json\ndef f(x):\n    return json.dumps({'a': x})\n"
    assert "AR-ENCODING" in rules(run(ArabicEncodingAnalyzer(), src))


def test_ar_encoding_ignores_ensure_ascii_false():
    src = "import json\ndef f(x):\n    return json.dumps({'a': x}, ensure_ascii=False)\n"
    assert rules(run(ArabicEncodingAnalyzer(), src)) == set()


def test_ar_encoding_tracks_from_import_alias():
    src = "from json import dumps as J\ndef f(x):\n    return J({'a': x})\n"
    assert "AR-ENCODING" in rules(run(ArabicEncodingAnalyzer(), src))


# --- AR-NUMERAL -------------------------------------------------------------

def test_ar_numeral_flags_int_on_user_text():
    src = "def f(message):\n    return int(message.text)\n"
    assert "AR-NUMERAL" in rules(run(ArabicNumeralAnalyzer(), src))


def test_ar_numeral_ignores_when_normalized():
    src = (
        "def f(message):\n"
        "    clean = normalize_arabic_indic_digits(message.text)\n"
        "    return int(clean)\n"
    )
    assert rules(run(ArabicNumeralAnalyzer(), src)) == set()


def test_ar_numeral_ignores_non_user_int():
    src = "def f(items):\n    return int(len(items))\n"
    assert rules(run(ArabicNumeralAnalyzer(), src)) == set()


# --- utility ----------------------------------------------------------------

def test_normalize_arabic_indic_digits():
    assert normalize_arabic_indic_digits("٢٠٢٦") == "2026"
    assert normalize_arabic_indic_digits("۵۶۷") == "567"  # extended (Persian/Urdu)
    assert normalize_arabic_indic_digits("qty ٣ pcs") == "qty 3 pcs"
    assert int(normalize_arabic_indic_digits("٢٥")) == 25


def test_normalize_fixes_ascii_only_regex_silent_loss():
    # Python's int() accepts "٢٥", but an explicit [0-9] regex silently drops
    # it — this is the real failure the digit normalizer prevents.
    import re

    assert re.findall(r"[0-9]+", "٢٥") == []  # silent data loss, no error
    assert re.findall(r"[0-9]+", normalize_arabic_indic_digits("٢٥")) == ["25"]


# --- AR-NORMALIZE -----------------------------------------------------------

def test_ar_normalize_flags_equality():
    src = "def f(m):\n    return m.strip() == %r\n" % NAAM
    assert "AR-NORMALIZE" in rules(run(ArabicNormalizeAnalyzer(), src))


def test_ar_normalize_flags_membership():
    src = "def f(m):\n    return m in [%r, %r]\n" % (NAAM, LAA)
    assert "AR-NORMALIZE" in rules(run(ArabicNormalizeAnalyzer(), src))


def test_ar_normalize_flags_startswith():
    src = "def f(m):\n    return m.startswith(%r)\n" % ar(0x0627, 0x0644)  # "ال"
    assert "AR-NORMALIZE" in rules(run(ArabicNormalizeAnalyzer(), src))


def test_ar_normalize_ignores_when_normalized():
    src = "def f(m):\n    return normalize_arabic(m) == normalize_arabic(%r)\n" % NAAM
    assert rules(run(ArabicNormalizeAnalyzer(), src)) == set()


def test_ar_normalize_ignores_latin_literal():
    src = "def f(m):\n    return m == 'yes'\n"
    assert rules(run(ArabicNormalizeAnalyzer(), src)) == set()


# --- AR-FILE-ENCODING / AR-ENCODE-ASCII -------------------------------------

def test_ar_file_encoding_flags_open_without_encoding():
    src = "def f(t):\n    open('reply.txt', 'w').write(t)\n"
    assert "AR-FILE-ENCODING" in rules(run(ArabicTextIoAnalyzer(), src))


def test_ar_file_encoding_ignores_with_encoding():
    src = "def f(t):\n    open('reply.txt', 'w', encoding='utf-8').write(t)\n"
    assert rules(run(ArabicTextIoAnalyzer(), src)) == set()


def test_ar_file_encoding_ignores_binary_mode():
    src = "def f(t):\n    open('reply.bin', 'wb').write(t)\n"
    assert rules(run(ArabicTextIoAnalyzer(), src)) == set()


def test_ar_encode_ascii_flags():
    src = "def f(t):\n    return t.encode('ascii')\n"
    assert "AR-ENCODE-ASCII" in rules(run(ArabicTextIoAnalyzer(), src))


def test_ar_encode_ascii_ignores_utf8():
    src = "def f(t):\n    return t.encode('utf-8')\n"
    assert rules(run(ArabicTextIoAnalyzer(), src)) == set()


# --- normalization toolkit --------------------------------------------------

def test_normalize_arabic_collapses_variants():
    voweled = ar(0x0646, 0x064E, 0x0639, 0x064E, 0x0645, 0x0652)  # نَعَمْ
    assert normalize_arabic(voweled) == normalize_arabic(NAAM)  # diacritics folded
    assert normalize_arabic(ar(0x0623)) == ar(0x0627)  # alef-hamza -> alef
    assert normalize_arabic(ar(0x0649)) == ar(0x064A)  # alef-maqsura -> ya
    assert normalize_arabic(ar(0x0629)) == ar(0x0647)  # ta-marbuta -> ha
    assert normalize_arabic(ar(0x0662, 0x0665)) == "25"  # digits folded too


def test_strip_tashkeel_and_tatweel():
    voweled = ar(0x0645, 0x064F, 0x062D, 0x0645, 0x0651, 0x062F)  # مُحَمّد
    assert strip_tashkeel(voweled) == ar(0x0645, 0x062D, 0x0645, 0x062F)  # محمد
    assert strip_tatweel(ar(0x0645, 0x0640, 0x0640, 0x0631)) == ar(0x0645, 0x0631)  # مرحبا skeleton


# --- AR-BIDI ----------------------------------------------------------------

def test_ar_bidi_flags_mixed_script_literal():
    label = ar(0x0627, 0x0644, 0x062D, 0x0627, 0x0644, 0x0629) + ": OK"  # "الحالة: OK"
    src = "def f():\n    return %r\n" % label
    assert "AR-BIDI" in rules(run(ArabicBidiAnalyzer(), src))


def test_ar_bidi_ignores_arabic_only():
    src = "def f():\n    return %r\n" % ar(0x0646, 0x0639, 0x0645)  # arabic only
    assert rules(run(ArabicBidiAnalyzer(), src)) == set()


def test_ar_bidi_ignores_docstring():
    doc = ar(0x0646, 0x0639, 0x0645) + " means yes"  # arabic+latin, but a docstring
    src = 'def f():\n    %r\n    return 1\n' % doc
    assert rules(run(ArabicBidiAnalyzer(), src)) == set()


def test_ar_bidi_suppressed_when_isolated():
    label = ar(0x0627, 0x0644, 0x062D, 0x0627, 0x0644, 0x0629) + " ABC"
    src = "def f():\n    x = wrap_ltr('ABC')\n    return %r + x\n" % label
    assert rules(run(ArabicBidiAnalyzer(), src)) == set()


def test_wrap_ltr_wraps_in_isolates():
    wrapped = wrap_ltr("ABC-12")
    assert wrapped == chr(0x2066) + "ABC-12" + chr(0x2069)


# --- config -----------------------------------------------------------------

def test_config_loads_from_pyproject(tmp_path):
    from fasih.config import load_config

    (tmp_path / "pyproject.toml").write_text(
        '[tool.fasih]\narabic = true\ndisable = ["AR-BIDI"]\n'
        'ignore = ["skip_*.py"]\nfail_on = "high"\n',
        encoding="utf-8",
    )
    cfg = load_config(str(tmp_path))
    assert cfg.arabic is True
    assert cfg.fail_on == "high"
    assert cfg.is_ignored("skip_me.py") and not cfg.is_ignored("keep.py")
    assert not cfg.allows("AR-BIDI") and cfg.allows("AR-NORMALIZE")


def test_config_disable_filters_findings():
    from fasih.config import Config

    result = scan(EXAMPLE, enable_arabic=True, config=Config(disable={"AR-BIDI"}))
    ids = rules(result.findings)
    assert "AR-BIDI" not in ids and "AR-NORMALIZE" in ids
    assert len(result.findings) == 9  # the other ten minus the disabled one


def test_scan_accepts_multiple_paths(tmp_path):
    (tmp_path / "a.py").write_text('import json\ndef f(x):\n    return json.dumps(x)\n', encoding="utf-8")
    (tmp_path / "b.py").write_text('def g(t):\n    return t.encode("ascii")\n', encoding="utf-8")
    result = scan([str(tmp_path / "a.py"), str(tmp_path / "b.py")], enable_arabic=True)
    assert {"AR-ENCODING", "AR-ENCODE-ASCII"} <= rules(result.findings)
    assert result.files_scanned == 2


# --- dashboard security -----------------------------------------------------

def _raw_get(port, host_header, path="/", extra=""):
    import socket

    conn = socket.create_connection(("127.0.0.1", port), timeout=5)
    conn.sendall(f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n{extra}Connection: close\r\n\r\n".encode())
    chunks = []
    while True:
        data = conn.recv(4096)
        if not data:
            break
        chunks.append(data)
    conn.close()
    return b"".join(chunks).decode("latin-1")


def _status(raw):
    return raw.split("\r\n", 1)[0].split()[1]


def test_dashboard_host_validation_and_security_headers():
    import threading
    from http.server import ThreadingHTTPServer
    from fasih.web import _Handler

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        ok = _raw_get(port, "localhost")
        assert _status(ok) == "200"
        assert "default-src 'none'" in ok
        assert "X-Frame-Options: DENY" in ok
        assert "X-Content-Type-Options: nosniff" in ok
        # DNS-rebinding: a spoofed Host must be rejected
        assert _status(_raw_get(port, "evil.com")) == "403"
        # cross-site browser request must be rejected
        assert _status(_raw_get(port, "localhost", extra="Sec-Fetch-Site: cross-site\r\n")) == "403"
    finally:
        server.shutdown()
        server.server_close()


def test_dashboard_requires_token_when_configured():
    import threading
    from http.server import ThreadingHTTPServer
    from fasih.web import _Handler

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.fasih_token = "tok-abc123"
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert _status(_raw_get(port, "localhost", "/")) == "403"  # missing token
        assert _status(_raw_get(port, "localhost", "/?token=wrong")) == "403"  # wrong token
        assert _status(_raw_get(port, "localhost", "/?token=tok-abc123")) == "200"  # correct
    finally:
        server.shutdown()
        server.server_close()


def test_dashboard_native_picker_redirects(monkeypatch):
    import threading
    from http.server import ThreadingHTTPServer
    import fasih.web as web

    server = ThreadingHTTPServer(("127.0.0.1", 0), web._Handler)
    server.fasih_token = "tok"
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        # a picked folder -> 303 redirect to a scan of that path
        monkeypatch.setattr(web, "_pick_folder", lambda: "/tmp/picked proj")
        resp = _raw_get(port, "localhost", "/pick?arabic=1&token=tok")
        assert _status(resp) == "303" and "Location: /?path=" in resp and "picked" in resp
        # cancel / no picker -> 303 back to the in-page browser
        monkeypatch.setattr(web, "_pick_folder", lambda: None)
        assert "browse=" in _raw_get(port, "localhost", "/pick?arabic=1&token=tok")
        # /pick still needs the token
        assert _status(_raw_get(port, "localhost", "/pick")) == "403"
    finally:
        server.shutdown()
        server.server_close()


# --- end-to-end -------------------------------------------------------------

def test_end_to_end_example_has_all_ten_and_only_ten():
    result = scan(EXAMPLE, enable_arabic=True)
    found = rules(result.findings)
    expected = {
        "FAIL-OPEN-GUARD",
        "ORPHANED-TOOL",
        "STRUCTURE-NOT-SEMANTICS",
        "HARDCODED-SECRET",
        "AR-ENCODING",
        "AR-NUMERAL",
        "AR-NORMALIZE",
        "AR-FILE-ENCODING",
        "AR-ENCODE-ASCII",
        "AR-BIDI",
    }
    assert found == expected, f"got {found}"
    # exactly one of each — the fixed half must contribute nothing
    assert len(result.findings) == 10, [f"{f.rule_id} L{f.line}" for f in result.findings]


def test_self_scan_is_clean():
    import fasih

    pkg_dir = os.path.dirname(fasih.__file__)
    result = scan(pkg_dir, enable_arabic=True)
    assert result.findings == [], [
        f"{f.rule_id} {os.path.basename(f.file)}:{f.line} — {f.message}" for f in result.findings
    ]


def test_web_dashboard_renders():
    import fasih
    from fasih.web import render_page

    page = render_page(EXAMPLE, True)
    assert "AR-NORMALIZE" in page and "finding(s)" in page
    clean = render_page(os.path.dirname(fasih.__file__), True)
    assert "No issues found" in clean


def test_web_expands_tilde():
    from fasih.web import _expand

    assert _expand("  ~/x  ") == os.path.join(os.path.expanduser("~"), "x")


def test_web_distinguishes_not_found_from_no_py(tmp_path):
    from fasih.web import render_page

    assert "Path not found" in render_page(str(tmp_path / "nope"), True, "t")
    (tmp_path / "readme.md").write_text("hi", encoding="utf-8")
    assert "no <code>.py</code> files" in render_page(str(tmp_path), True, "t")


def test_web_folder_browser_lists_subdirs(tmp_path):
    from fasih.web import render_browse_page

    (tmp_path / "proj").mkdir()
    page = render_browse_page(str(tmp_path), True, "t")
    assert "Scan this folder" in page
    assert "proj" in page and "browse=" in page


# --- auto-fix ---------------------------------------------------------------

def _apply(analyzer, src):
    from fasih.fixes import apply_edits

    findings = list(analyzer.check(ast.parse(src), "t.py", src))
    edits = [(f.fix_start, f.fix_end, f.fix_replacement) for f in findings if f.fixable]
    fixed = apply_edits(src, edits)
    ast.parse(fixed)  # must stay valid
    return fixed


def test_autofix_ar_encoding_adds_ensure_ascii():
    fixed = _apply(ArabicEncodingAnalyzer(), 'import json\ndef f(x):\n    return json.dumps({"k": x})\n')
    assert 'json.dumps({"k": x}, ensure_ascii=False)' in fixed


def test_autofix_file_encoding_and_ascii_encode():
    src = 'def f(t):\n    open("x.txt", "w").write(t)\n    return t.encode("ascii")\n'
    fixed = _apply(ArabicTextIoAnalyzer(), src)
    assert 'open("x.txt", "w", encoding="utf-8")' in fixed
    assert '.encode("utf-8")' in fixed


def test_autofix_byte_offsets_survive_arabic():
    # Arabic before the call means byte != char offset; the edit must still land
    # correctly and leave the Arabic intact.
    key = ar(0x0631, 0x0633, 0x0627, 0x0644, 0x0629)  # رسالة
    src = "import json\ndef f(x):\n    return json.dumps({%r: x})\n" % key
    fixed = _apply(ArabicEncodingAnalyzer(), src)
    assert key in fixed  # Arabic key untouched
    assert fixed.count("ensure_ascii=False") == 1
    assert "}, ensure_ascii=False)" in fixed  # landed at the right place


def test_autofix_apply_file_is_atomic_and_validated(tmp_path):
    from fasih.fixes import apply_file

    p = tmp_path / "m.py"
    p.write_text('import json\ndef f(x):\n    return json.dumps({"k": x})\n', encoding="utf-8")
    findings = list(ArabicEncodingAnalyzer().check(ast.parse(p.read_text(encoding="utf-8")), str(p), p.read_text(encoding="utf-8")))
    assert apply_file(str(p), findings) == 1
    assert "ensure_ascii=False" in p.read_text(encoding="utf-8")
    ast.parse(p.read_text(encoding="utf-8"))  # still valid on disk
