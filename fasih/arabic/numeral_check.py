"""AR-NUMERAL — parsing user text with int()/float() without normalizing
Arabic-Indic digits first.

``int("٢٥")`` raises ``ValueError``: Python's ``int``/``float`` only parse
ASCII ``0-9``. An Arabic-script user typing quantities, OTPs, prices or dates
in a WhatsApp bot or a form will send ``٠-٩`` (Arabic-Indic) or ``۰-۹``
(Extended Arabic-Indic, used for Persian/Urdu), and the parse crashes or the
value is silently dropped.

This module ships :func:`normalize_arabic_indic_digits` as a genuinely useful
runtime utility (``from fasih import normalize_arabic_indic_digits``) *and* an
analyzer that flags un-normalized ``int()``/``float()`` calls on things that
look like user input. The "already normalizes" suppression is scoped to the
enclosing function (and its enclosing scopes) — not the whole file — so an
unrelated later function that happens to call a normalizer does not mask a real
bug elsewhere.
"""

from __future__ import annotations

import ast
from typing import Iterable, List

from ..findings import Finding, Severity
from ..analyzers.base import Analyzer, call_name, source_line

# U+0660..U+0669 (Arabic-Indic) and U+06F0..U+06F9 (Extended Arabic-Indic).
_ARABIC_INDIC = "٠١٢٣٤٥٦٧٨٩"
_EXT_ARABIC_INDIC = "۰۱۲۳۴۵۶۷۸۹"
_DIGIT_MAP = {ord(ch): str(i) for i, ch in enumerate(_ARABIC_INDIC)}
_DIGIT_MAP.update({ord(ch): str(i) for i, ch in enumerate(_EXT_ARABIC_INDIC)})


def normalize_arabic_indic_digits(text: str) -> str:
    """Convert Arabic-Indic (٠-٩) and Extended Arabic-Indic (۰-۹) digits to
    ASCII ``0-9`` so ``int()``/``float()`` and numeric comparisons work on
    input typed by Arabic-script users. Non-digit characters are untouched.

    >>> normalize_arabic_indic_digits("٢٠٢٦")
    '2026'
    >>> int(normalize_arabic_indic_digits("الكمية: ٥".split()[-1]))
    5
    """
    return text.translate(_DIGIT_MAP)


_INPUTISH_NAMES = {
    "text", "message", "msg", "body", "content", "input", "user_input", "userinput",
    "query", "q", "payload", "reply", "answer", "value", "val", "raw", "data",
    "amount", "qty", "quantity", "count", "number", "num", "price", "phone",
    "otp", "code", "pin", "digits", "arg", "argument", "response", "caption",
}
_INPUTISH_ATTRS = {
    "text", "body", "message", "content", "caption", "value", "data", "answer",
    "form", "args", "params", "json", "values",
}
_NORMALIZER_TOKENS = (
    "normalize", "arabic", "to_ascii", "ascii_digits", "translate_digits",
    "westernize", "convert_digits", "maketrans",
)


class ArabicNumeralAnalyzer(Analyzer):
    rule_id = "AR-NUMERAL"

    def check(self, tree: ast.AST, filename: str, source: str) -> Iterable[Finding]:
        findings: List[Finding] = []
        self._scan_scope(tree, inherited_norm=False, filename=filename, source=source, out=findings)
        return findings

    def _scan_scope(self, scope, inherited_norm, filename, source, out):
        own = list(self._iter_own(scope))
        normalized = inherited_norm or any(
            isinstance(n, ast.Call) and self._is_normalizer(n.func) for n in own
        )
        for node in own:
            if (
                isinstance(node, ast.Call)
                and self._is_int_float(node.func)
                and node.args
                and not normalized
                and self._looks_like_user_input(node.args[0])
            ):
                out.append(self._finding(node, filename, source))
        for node in own:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._scan_scope(node, normalized, filename, source, out)

    @staticmethod
    def _iter_own(scope):
        """Yield nodes in ``scope``'s body without descending into nested
        function scopes (those are recursed into separately)."""
        stack = list(ast.iter_child_nodes(scope))
        while stack:
            node = stack.pop()
            yield node
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            stack.extend(ast.iter_child_nodes(node))

    # -- predicates ----------------------------------------------------------

    @staticmethod
    def _is_int_float(func: ast.AST) -> bool:
        return isinstance(func, ast.Name) and func.id in ("int", "float")

    def _is_normalizer(self, func: ast.AST) -> bool:
        name = call_name(func).lower()
        return bool(name) and any(tok in name for tok in _NORMALIZER_TOKENS)

    def _looks_like_user_input(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id.lower() in _INPUTISH_NAMES
        if isinstance(node, ast.Attribute):
            return node.attr.lower() in _INPUTISH_ATTRS or self._looks_like_user_input(node.value)
        if isinstance(node, ast.Subscript):
            return self._looks_like_user_input(node.value)
        if isinstance(node, ast.Call):
            name = call_name(node.func).lower()
            return name == "input" or name.endswith(".get") or "form" in name or "json" in name
        return False

    def _finding(self, node, filename, source) -> Finding:
        fname = call_name(node.func)
        return Finding(
            rule_id=self.rule_id,
            severity=Severity.MEDIUM,
            message=(
                f"{fname}() parses user-supplied text without normalizing "
                f"Arabic-Indic digits (٠-٩); Arabic numeral input will raise ValueError."
            ),
            file=filename,
            line=node.lineno,
            column=node.col_offset,
            why=(
                "int('٢٥') raises ValueError — int()/float() only parse ASCII 0-9. When an "
                "Arabic-script user types numerals (WhatsApp, forms, voice-to-text), the "
                "parse crashes or the value is dropped, and the bug only shows up for "
                "Arabic users."
            ),
            fix="Normalize first, e.g. int(normalize_arabic_indic_digits(text)).",
            snippet=source_line(source, node.lineno),
        )
