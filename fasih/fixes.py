"""Auto-fix support.

A :class:`~fasih.findings.Finding` may carry a concrete fix: replace the source
bytes ``[fix_start, fix_end)`` with ``fix_replacement``. Byte offsets are used
throughout because Python's ``ast`` column offsets are UTF-8 byte offsets, so a
character-based edit would corrupt any file containing Arabic.

Only mechanical, meaning-preserving fixes are ever emitted (adding
``ensure_ascii=False`` / ``encoding="utf-8"``, switching a doomed ``ascii``
codec to ``utf-8``). Applying is opt-in, atomic, and re-parses the result before
writing, so it can never leave broken source on disk.
"""

from __future__ import annotations

import ast
import difflib
import os
import tempfile
from typing import List, Tuple


def line_byte_starts(source: str) -> List[int]:
    """Byte offset of the start of each 1-indexed source line."""
    starts = [0]
    total = 0
    for line in source.split("\n"):
        total += len(line.encode("utf-8")) + 1  # + the newline
        starts.append(total)
    return starts


def _byte_offset(starts: List[int], lineno: int, col: int) -> int:
    return starts[lineno - 1] + col


def node_span(source: str, node: ast.AST) -> Tuple[int, int]:
    """(start, end) byte offsets of an AST node in ``source``."""
    starts = line_byte_starts(source)
    return (
        _byte_offset(starts, node.lineno, node.col_offset),
        _byte_offset(starts, node.end_lineno, node.end_col_offset),
    )


def add_kwarg_edit(source: str, call: ast.Call, kwarg_text: str) -> Tuple[int, int, str]:
    """Edit that adds ``kwarg_text`` (e.g. ``ensure_ascii=False``) to a call,
    after the last existing argument (or inside empty parens)."""
    starts = line_byte_starts(source)
    positioned = list(call.args) + [kw.value for kw in call.keywords if kw.value is not None]
    if positioned:
        last = max(positioned, key=lambda n: (n.end_lineno, n.end_col_offset))
        pos = _byte_offset(starts, last.end_lineno, last.end_col_offset)
        return (pos, pos, ", " + kwarg_text)
    end = _byte_offset(starts, call.end_lineno, call.end_col_offset)
    return (end - 1, end - 1, kwarg_text)  # before the closing ")"


def replace_node_edit(source: str, node: ast.AST, new_text: str) -> Tuple[int, int, str]:
    start, end = node_span(source, node)
    return (start, end, new_text)


def apply_edits(source: str, edits: List[Tuple[int, int, str]]) -> str:
    """Apply (start, end, text) byte-span edits. Non-overlapping; applied
    right-to-left so earlier offsets stay valid."""
    data = bytearray(source.encode("utf-8"))
    for start, end, text in sorted(edits, key=lambda e: e[0], reverse=True):
        data[start:end] = text.encode("utf-8")
    return data.decode("utf-8")


def _edits_for(findings) -> List[Tuple[int, int, str]]:
    seen = set()
    edits = []
    for f in findings:
        if not f.fixable:
            continue
        key = (f.fix_start, f.fix_end, f.fix_replacement)
        if key in seen:
            continue
        seen.add(key)
        edits.append((f.fix_start, f.fix_end, f.fix_replacement))
    return edits


def preview_file(path: str, findings) -> str:
    """Unified diff of what ``--fix`` would change in ``path`` (or "")."""
    edits = _edits_for(findings)
    if not edits:
        return ""
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    new = apply_edits(source, edits)
    if new == source:
        return ""
    rel = os.path.relpath(path)
    diff = difflib.unified_diff(
        source.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=rel, tofile=rel + " (fixed)",
    )
    return "".join(diff)


def apply_file(path: str, findings) -> int:
    """Apply fixes to ``path`` atomically. Returns the number of edits applied,
    or -1 if the result would not parse (in which case nothing is written)."""
    edits = _edits_for(findings)
    if not edits:
        return 0
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    new = apply_edits(source, edits)
    if new == source:
        return 0
    try:
        ast.parse(new)  # never write source that doesn't parse
    except SyntaxError:
        return -1
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".fasih-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(new)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return len(edits)
