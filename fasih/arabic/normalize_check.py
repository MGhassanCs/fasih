"""AR-NORMALIZE -- matching Arabic text without normalizing it first.

This is the most frequent Arabic-pipeline bug. The same word has many valid
spellings (alef variants, alef-maqsura vs ya, ta-marbuta vs ha, tatweel, and
optional diacritics), so a raw ``==`` / ``in`` / ``.startswith()`` against a
fixed Arabic string matches only one of them. Intent detection, keyword guards,
routing tables and dedup then silently drop real user input -- and only for
Arabic users.

We flag an Arabic string literal used in a matching context (equality,
membership, or a matching str-method) when the enclosing function does not call
a normalizer. The "already normalizes" suppression is scoped to the enclosing
function (like AR-NUMERAL), not the whole file.
"""

from __future__ import annotations

import ast
from typing import Iterable, List, Optional

from ..findings import Finding, Severity
from ..analyzers.base import Analyzer, call_name, iter_own_scope, source_line

_NORMALIZER_TOKENS = ("normalize", "normalise", "strip_tashkeel", "strip_tatweel", "canonical")
_MATCH_METHODS = ("startswith", "endswith", "find", "rfind", "index", "count")


def contains_arabic_letters(text: str) -> bool:
    """True if the string contains an Arabic *letter* (not just Arabic-Indic
    digits or diacritics, which are handled by other rules)."""
    for ch in text:
        o = ord(ch)
        if (0x0621 <= o <= 0x064A) or (0x0671 <= o <= 0x06D3) or (0xFB50 <= o <= 0xFDFF) or (0xFE70 <= o <= 0xFEFF):
            return True
    return False


class ArabicNormalizeAnalyzer(Analyzer):
    rule_id = "AR-NORMALIZE"

    def check(self, tree: ast.AST, filename: str, source: str) -> Iterable[Finding]:
        findings: List[Finding] = []
        self._scan(tree, inherited_norm=False, filename=filename, source=source, out=findings)
        return findings

    def _scan(self, scope, inherited_norm, filename, source, out):
        own = list(iter_own_scope(scope))
        normalized = inherited_norm or any(
            isinstance(n, ast.Call) and self._is_normalizer(n.func) for n in own
        )
        if not normalized:
            for node in own:
                if self._is_match_against_arabic(node):
                    out.append(self._finding(node, filename, source))
        for node in own:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._scan(node, normalized, filename, source, out)

    def _is_normalizer(self, func) -> bool:
        name = call_name(func).lower()
        return bool(name) and any(tok in name for tok in _NORMALIZER_TOKENS)

    def _is_match_against_arabic(self, node) -> bool:
        # x == "arabic" / "arabic" != x / "arabic" in x / x in ["arabic", ...]
        if isinstance(node, ast.Compare):
            if any(isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)) for op in node.ops):
                for operand in [node.left, *node.comparators]:
                    if self._is_arabic_str(operand):
                        return True
                    if isinstance(operand, (ast.List, ast.Set, ast.Tuple)):
                        if any(self._is_arabic_str(elt) for elt in operand.elts):
                            return True
        # x.startswith("arabic") / x.find("arabic") / ...
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in _MATCH_METHODS and any(self._is_arabic_str(a) for a in node.args):
                return True
        return False

    @staticmethod
    def _is_arabic_str(node) -> bool:
        return (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and contains_arabic_letters(node.value)
        )

    def _finding(self, node, filename, source) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=Severity.MEDIUM,
            message="Arabic text is matched (==/in/startswith) without normalization; spelling variants silently miss.",
            file=filename,
            line=node.lineno,
            column=node.col_offset,
            why=(
                "The same Arabic word has several written forms: alef variants (hamza forms "
                "vs bare alef), alef-maqsura vs ya, ta-marbuta vs ha, the tatweel elongation, "
                "and optional diacritics. A raw == or `in` against a fixed string matches only "
                "one spelling, so real input with a different alef or an extra harakat is "
                "silently rejected -- breaking intent detection, keyword guards, routing and "
                "dedup, only for Arabic users."
            ),
            fix=(
                "Normalize both sides first, e.g. normalize_arabic(text) == normalize_arabic(expected). "
                "fasih ships normalize_arabic() / strip_tashkeel() / strip_tatweel()."
            ),
            snippet=source_line(source, node.lineno),
        )
