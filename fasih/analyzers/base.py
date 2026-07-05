"""Analyzer base class and small AST helpers shared across analyzers."""

from __future__ import annotations

import ast
from typing import Iterable

from ..findings import Finding


class Analyzer:
    """Base class for all analyzers.

    There are two flavours, and an analyzer may be either or both:

    * **Per-file** analyzers override :meth:`check` — called once per source
      file with the parsed tree and the raw source.
    * **Whole-project** analyzers override :meth:`collect` (called once per
      file to accumulate state) and :meth:`finalize` (called once, after
      every file has been collected, to emit cross-file findings).

    Defaults are no-ops so the engine can call every hook uniformly without
    caring which flavour a given analyzer is.
    """

    rule_id: str = ""

    def check(self, tree: ast.AST, filename: str, source: str) -> Iterable[Finding]:
        return []

    def collect(self, tree: ast.AST, filename: str, source: str) -> None:
        return None

    def finalize(self) -> Iterable[Finding]:
        return []


def source_line(source: str, lineno: int) -> str:
    """Return the stripped source text at ``lineno`` (1-indexed), or ""."""
    lines = source.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


def call_name(func: ast.AST) -> str:
    """Best-effort dotted name for a call target, e.g. ``a.b.c`` for
    ``a.b.c(...)`` or ``open`` for ``open(...)``. Returns "" if it can't be
    resolved to attribute/name chain (e.g. a call on a subscript)."""
    parts = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    else:
        # unresolved base (subscript, call, etc.) — keep what we have
        pass
    return ".".join(reversed(parts))
