"""FAIL-OPEN-GUARD — a guardrail wrapped in try/except that fails *open*.

The antipattern this catches is the single most expensive one I have seen in
production agents: a safety / moderation / policy check is wrapped in a broad
``try/except`` whose handler swallows the exception and lets execution
continue as if the check had passed. When the guardrail then errors (a
timeout, a rate limit, a malformed input) the request is *allowed*, not
blocked. Guardrails must fail closed.

Detection is intentionally specific to keep false positives at zero:

1. the ``try`` body must contain a call that looks like a guardrail, and
2. a *broad* handler (``except:`` / ``except Exception`` / ``BaseException``)
   must be *permissive* — it neither re-raises, nor calls a deny/block
   function, nor returns a non-permissive verdict; it either falls straight
   through to the guarded action or returns ``True``/``None``.
"""

from __future__ import annotations

import ast
from typing import Iterable, List, Optional

from ..findings import Finding, Severity
from .base import Analyzer, call_name, source_line

# Substrings that mark a call as a safety gate. Deliberately specific: generic
# words like "validate"/"check" alone are too noisy to include here.
_GUARDRAIL_TOKENS = (
    "guardrail",
    "guard",
    "moderat",  # moderate / moderation
    "is_safe",
    "is_allowed",
    "safety",
    "check_policy",
    "policy_check",
    "sanitize",
    "jailbreak",
    "toxicity",
    "profanity",
    "content_filter",
    "nsfw",
    "input_guard",
    "output_guard",
)

# Function-name substrings that mean a handler explicitly denies (fails closed).
_DENY_TOKENS = ("deny", "block", "reject", "refuse", "abort", "forbid")

# String-return substrings that also read as a deny verdict.
_DENY_STRINGS = ("block", "deny", "reject", "refuse", "unsafe", "forbidden", "not allowed")


class FailOpenAnalyzer(Analyzer):
    rule_id = "FAIL-OPEN-GUARD"

    def check(self, tree: ast.AST, filename: str, source: str) -> Iterable[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            guard = self._first_guardrail_call(node.body)
            if guard is None:
                continue
            if not self._has_failopen_handler(node.handlers):
                continue
            name = call_name(guard.func) or "guardrail"
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    message=(
                        f"Guardrail call `{name}()` is wrapped in a try/except that "
                        f"swallows the error and continues — this fails OPEN."
                    ),
                    file=filename,
                    line=guard.lineno,
                    column=guard.col_offset,
                    why=(
                        "If the safety check raises (timeout, API error, bad input), the "
                        "handler lets execution proceed to the guarded action, so a failure "
                        "of the guardrail silently ALLOWS the request. Safety checks must "
                        "fail closed: an error should deny, not permit."
                    ),
                    fix=(
                        "In the handler, deny by default — re-raise, return the blocked "
                        "verdict, or route to a safe fallback. Never fall through to the "
                        "guarded action as if the check had passed."
                    ),
                    snippet=source_line(source, guard.lineno),
                )
            )
        return findings

    # -- guardrail detection -------------------------------------------------

    def _first_guardrail_call(self, body: List[ast.stmt]) -> Optional[ast.Call]:
        for stmt in body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    name = call_name(node.func).lower()
                    if name and any(tok in name for tok in _GUARDRAIL_TOKENS):
                        return node
        return None

    # -- handler classification ---------------------------------------------

    def _has_failopen_handler(self, handlers: List[ast.ExceptHandler]) -> bool:
        for handler in handlers:
            if self._is_broad(handler) and self._verdict(handler) == "open":
                return True
        return False

    def _is_broad(self, handler: ast.ExceptHandler) -> bool:
        t = handler.type
        if t is None:  # bare `except:`
            return True
        names = [self._exc_name(e) for e in t.elts] if isinstance(t, ast.Tuple) else [self._exc_name(t)]
        return any(n in ("Exception", "BaseException") for n in names)

    @staticmethod
    def _exc_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    def _verdict(self, handler: ast.ExceptHandler) -> str:
        """Return "open" (fails open / permissive) or "closed" (fails closed)."""
        for node in ast.walk(handler):
            if isinstance(node, ast.Raise):
                return "closed"
            if isinstance(node, ast.Call):
                name = call_name(node.func).lower()
                if name and any(tok in name for tok in _DENY_TOKENS):
                    return "closed"

        for node in ast.walk(handler):
            if isinstance(node, ast.Return):
                value = node.value
                if value is None or self._is_permissive_const(value):
                    continue  # bare return / return True / return None -> permissive
                if self._is_denyish_string(value):
                    return "closed"
                # returns some other concrete value (a fallback, "blocked", …):
                # it diverts control instead of proceeding -> fail closed.
                return "closed"
        return "open"

    @staticmethod
    def _is_permissive_const(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and node.value in (True, None)

    @staticmethod
    def _is_denyish_string(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            return any(tok in low for tok in _DENY_STRINGS)
        return False
