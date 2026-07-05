"""Unit tests per analyzer, plus an end-to-end fixture scan and a self-scan
that enforces fasih's zero-false-positive guarantee on its own source."""

import ast
import os

import pytest

from fasih import normalize_arabic_indic_digits
from fasih.rules_engine import scan
from fasih.analyzers.fail_open import FailOpenAnalyzer
from fasih.analyzers.orphaned_tools import OrphanedToolAnalyzer
from fasih.analyzers.eval_structure import EvalStructureAnalyzer
from fasih.analyzers.secrets import SecretsAnalyzer
from fasih.arabic.encoding_check import ArabicEncodingAnalyzer
from fasih.arabic.numeral_check import ArabicNumeralAnalyzer

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


# --- end-to-end -------------------------------------------------------------

def test_end_to_end_example_has_all_six_and_only_six():
    result = scan(EXAMPLE, enable_arabic=True)
    found = rules(result.findings)
    expected = {
        "FAIL-OPEN-GUARD",
        "ORPHANED-TOOL",
        "STRUCTURE-NOT-SEMANTICS",
        "HARDCODED-SECRET",
        "AR-ENCODING",
        "AR-NUMERAL",
    }
    assert found == expected, f"got {found}"
    # exactly one of each — the fixed half must contribute nothing
    assert len(result.findings) == 6, [f"{f.rule_id} L{f.line}" for f in result.findings]


def test_self_scan_is_clean():
    import fasih

    pkg_dir = os.path.dirname(fasih.__file__)
    result = scan(pkg_dir, enable_arabic=True)
    assert result.findings == [], [
        f"{f.rule_id} {os.path.basename(f.file)}:{f.line} — {f.message}" for f in result.findings
    ]
