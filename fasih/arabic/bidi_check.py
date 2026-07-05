"""AR-BIDI -- Arabic and Latin scripts mixed in one string literal.

Dropping a Latin run (a word, a URL, a code like "ABC-12") into Arabic RTL text
without a bidi isolate lets the Unicode bidi algorithm reorder it visually, so
what the developer typed and what the user sees diverge. This flags a single
string literal that contains *both* Arabic letters and ASCII Latin letters --
the reliably-scrambling case.

It is advisory (LOW): it does not fire on Arabic-only or Latin-only strings, it
skips docstrings, and it is suppressed inside a function that already calls a
bidi isolate helper (``wrap_ltr`` / ``isolate`` / anything with bidi/lri/rli).
"""

from __future__ import annotations

import ast
from typing import Iterable, List

from ..findings import Finding, Severity
from ..analyzers.base import Analyzer, call_name, iter_own_scope, source_line
from .normalize_check import contains_arabic_letters

_BIDI_HELPER_TOKENS = ("wrap_ltr", "wrap_rtl", "isolate", "bidi", "lri", "rli", "lrm", "rlm")


def _contains_latin_letters(text: str) -> bool:
    return any(ch.isascii() and ch.isalpha() for ch in text)


class ArabicBidiAnalyzer(Analyzer):
    rule_id = "AR-BIDI"

    def check(self, tree: ast.AST, filename: str, source: str) -> Iterable[Finding]:
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, (ast.Constant, ast.JoinedStr)):
                docstrings.add(id(node.value))
        findings: List[Finding] = []
        self._scan(tree, inherited_iso=False, filename=filename, source=source, docstrings=docstrings, out=findings)
        return findings

    def _scan(self, scope, inherited_iso, filename, source, docstrings, out):
        own = list(iter_own_scope(scope))
        isolated = inherited_iso or any(
            isinstance(n, ast.Call) and self._is_bidi_helper(n.func) for n in own
        )
        if not isolated:
            for node in own:
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and id(node) not in docstrings
                    and contains_arabic_letters(node.value)
                    and _contains_latin_letters(node.value)
                ):
                    out.append(self._finding(node, filename, source))
        for node in own:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._scan(node, isolated, filename, source, docstrings, out)

    def _is_bidi_helper(self, func) -> bool:
        name = call_name(func).lower()
        return bool(name) and any(tok in name for tok in _BIDI_HELPER_TOKENS)

    def _finding(self, node, filename, source) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=Severity.LOW,
            message="Arabic and Latin scripts mixed in one string literal may render out of order (bidi).",
            file=filename,
            line=node.lineno,
            column=node.col_offset,
            why=(
                "Latin words, numbers or URLs placed inside Arabic RTL text can be reordered "
                "by the Unicode bidi algorithm, so the rendered order differs from the source. "
                "It shows up in messages, PDFs and notifications shown to Arabic users."
            ),
            fix=(
                "Isolate the LTR run with bidi isolates, e.g. "
                'f"...{wrap_ltr(order_id)}..." -- fasih ships wrap_ltr()/isolate().'
            ),
            snippet=source_line(source, node.lineno),
        )
