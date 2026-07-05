"""AR-FILE-ENCODING and AR-ENCODE-ASCII -- text I/O that mangles Arabic.

* ``open(path, "w")`` without ``encoding=`` uses the platform's *locale* encoding
  (UTF-8 on modern macOS/Linux, but cp1252 on Windows, and sometimes ASCII in
  containers). Writing Arabic then produces mojibake or a UnicodeEncodeError, and
  the same file written on one machine is unreadable on another. pathlib's
  ``Path.write_text``/``read_text`` have the same default. (This is the same idea
  as pylint's W1514; here it is framed for bilingual pipelines.)

* ``"...".encode("ascii")`` / ``"latin-1"`` cannot represent Arabic at all and
  raises ``UnicodeEncodeError`` on the first Arabic character.
"""

from __future__ import annotations

import ast
from typing import Iterable, List, Optional

from ..findings import Finding, Severity
from ..analyzers.base import source_line
from ..fixes import add_kwarg_edit, replace_node_edit

_ASCII_CODECS = {
    "ascii", "us-ascii", "latin-1", "latin1", "latin_1",
    "iso-8859-1", "iso8859-1", "cp1252", "windows-1252",
}


class ArabicTextIoAnalyzer:
    """Implements the analyzer interface (check/collect/finalize) without
    subclassing Analyzer, since it emits two different rule ids."""

    rule_id = "AR-FILE-ENCODING"

    def check(self, tree: ast.AST, filename: str, source: str) -> Iterable[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if self._is_open(func):
                if self._is_text_mode(node) and not self._has_encoding(node):
                    findings.append(self._file_finding(node, filename, source, "open()"))
            elif isinstance(func, ast.Attribute) and func.attr in ("write_text", "read_text"):
                if not self._has_encoding(node):
                    findings.append(self._file_finding(node, filename, source, "Path." + func.attr + "()"))
            elif isinstance(func, ast.Attribute) and func.attr == "encode":
                codec = self._first_str_arg(node)
                if codec is not None and codec.strip().lower() in _ASCII_CODECS:
                    findings.append(self._encode_finding(node, node.args[0], codec, filename, source))
        return findings

    def collect(self, tree, filename, source):
        return None

    def finalize(self):
        return []

    # -- open() detection ----------------------------------------------------

    @staticmethod
    def _is_open(func) -> bool:
        if isinstance(func, ast.Name):
            return func.id == "open"
        if isinstance(func, ast.Attribute) and func.attr == "open":
            return isinstance(func.value, ast.Name) and func.value.id in ("io", "codecs")
        return False

    def _is_text_mode(self, call: ast.Call) -> bool:
        mode = self._mode(call)
        if mode is None:
            return True  # default mode is "r" -> text
        if not isinstance(mode, str):
            return False  # dynamic mode -> can't prove it's text, don't flag
        return "b" not in mode

    def _mode(self, call: ast.Call):
        if len(call.args) >= 2:
            arg = call.args[1]
            return arg.value if isinstance(arg, ast.Constant) else arg  # non-const -> sentinel
        for kw in call.keywords:
            if kw.arg == "mode":
                return kw.value.value if isinstance(kw.value, ast.Constant) else kw.value
        return None

    @staticmethod
    def _has_encoding(call: ast.Call) -> bool:
        for kw in call.keywords:
            if kw.arg == "encoding" or kw.arg is None:  # explicit or **kwargs spread
                return True
        return False

    @staticmethod
    def _first_str_arg(call: ast.Call) -> Optional[str]:
        if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            return call.args[0].value
        return None

    # -- findings ------------------------------------------------------------

    def _file_finding(self, node, filename, source, what) -> Finding:
        fix_start, fix_end, fix_text = add_kwarg_edit(source, node, 'encoding="utf-8"')
        return Finding(
            rule_id="AR-FILE-ENCODING",
            severity=Severity.MEDIUM,
            message=what + " opens text without encoding=\"utf-8\"; Arabic depends on the machine's locale.",
            file=filename,
            line=node.lineno,
            column=node.col_offset,
            why=(
                "Without an explicit encoding, Python uses the platform locale (cp1252 on "
                "Windows, sometimes ASCII in containers). Writing Arabic then mojibakes or "
                "raises UnicodeEncodeError, and a file written on one machine is unreadable on "
                "another."
            ),
            fix="Pass encoding=\"utf-8\" (and errors=\"strict\") to open()/write_text()/read_text().",
            snippet=source_line(source, node.lineno),
            fix_start=fix_start,
            fix_end=fix_end,
            fix_replacement=fix_text,
        )

    def _encode_finding(self, node, codec_node, codec, filename, source) -> Finding:
        fix_start, fix_end, fix_text = replace_node_edit(source, codec_node, '"utf-8"')
        return Finding(
            rule_id="AR-ENCODE-ASCII",
            severity=Severity.MEDIUM,
            message="encode(\"" + codec + "\") cannot represent Arabic and raises UnicodeEncodeError on it.",
            file=filename,
            line=node.lineno,
            column=node.col_offset,
            why=(
                "ascii/latin-1 cover no Arabic code points, so the first Arabic character "
                "throws UnicodeEncodeError (or, with errors=\"ignore\", silently drops the text)."
            ),
            fix="Encode as UTF-8: text.encode(\"utf-8\").",
            snippet=source_line(source, node.lineno),
            fix_start=fix_start,
            fix_end=fix_end,
            fix_replacement=fix_text,
        )
