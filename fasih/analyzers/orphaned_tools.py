"""ORPHANED-TOOL — a tool/fetcher defined but never invoked anywhere.

This is deliberately a *whole-project* analyzer. In a real agent a tool is
usually **defined** in one module and **wired in** somewhere else, so a
per-file check would flag every tool as orphaned. Instead we collect two
things across the entire scan:

* every tool/fetcher **definition** (by decorator or by naming convention), and
* every **reference** to any name — attribute accesses and, crucially, string
  literals, because tools are frequently registered by name string
  (``tools=["fetch_weather"]``, dispatch dicts, MCP manifests).

Counting string references as uses is a conservative choice: it means we would
rather miss a genuinely-dead tool than falsely flag one that is wired up
dynamically. Zero false positives matters more than catching every last case.
"""

from __future__ import annotations

import ast
import re
from typing import Iterable, List, Set, Tuple

from ..findings import Finding, Severity
from .base import Analyzer

_TOOL_DECORATOR_TOKENS = ("tool", "fetcher")
_TOOL_NAME_RE = re.compile(r"(^fetch_|^tool_|_tool$|_fetcher$)")
_SKIP_NAMES = {"main", "setup", "teardown", "run", "handler"}


class OrphanedToolAnalyzer(Analyzer):
    rule_id = "ORPHANED-TOOL"

    def __init__(self) -> None:
        self._defs: List[Tuple[str, str, int]] = []  # (name, file, line)
        self._used: Set[str] = set()

    def collect(self, tree: ast.AST, filename: str, source: str) -> None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._is_tool_def(node):
                    self._defs.append((node.name, filename, node.lineno))

            # Record references. A function's own def does not create a Load of
            # its name, so a tool only appears here when it is genuinely used.
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                self._used.add(node.id)
            elif isinstance(node, ast.Attribute):
                self._used.add(node.attr)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                self._used.add(node.value)

    def finalize(self) -> Iterable[Finding]:
        findings: List[Finding] = []
        for name, filename, line in self._defs:
            if name in self._used:
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.MEDIUM,
                    message=(
                        f"Tool/fetcher `{name}` is defined but never invoked or "
                        f"registered anywhere in the scanned project."
                    ),
                    file=filename,
                    line=line,
                    why=(
                        "An orphaned tool is dead wiring. Either it should be registered "
                        "with the agent/pipeline and isn't — a silent capability or data "
                        "gap where you think a fetcher runs but it never does — or it is "
                        "leftover code that should be removed."
                    ),
                    fix=(
                        "Register/invoke the tool where the agent's tools are wired, or "
                        "delete it. If it is dispatched dynamically by name, make sure the "
                        "string literal matches the function name exactly."
                    ),
                )
            )
        return findings

    # -- tool detection ------------------------------------------------------

    def _is_tool_def(self, node) -> bool:
        if self._has_tool_decorator(node):
            return True
        if node.name.startswith("_"):
            return False  # private helpers are not tools unless explicitly decorated
        if node.name in _SKIP_NAMES:
            return False
        return bool(_TOOL_NAME_RE.search(node.name))

    def _has_tool_decorator(self, node) -> bool:
        for dec in node.decorator_list:
            name = self._decorator_name(dec).lower()
            if any(tok in name for tok in _TOOL_DECORATOR_TOKENS):
                return True
        return False

    @staticmethod
    def _decorator_name(dec: ast.AST) -> str:
        if isinstance(dec, ast.Call):
            dec = dec.func
        parts = []
        while isinstance(dec, ast.Attribute):
            parts.append(dec.attr)
            dec = dec.value
        if isinstance(dec, ast.Name):
            parts.append(dec.id)
        return ".".join(reversed(parts))
