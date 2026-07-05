"""Walk a target path, parse each file once, and run every analyzer over it.

Per-file analyzers see one file at a time; whole-project analyzers accumulate
via ``collect`` and emit at the end via ``finalize``. Every analyzer parses the
same AST — the engine parses each file exactly once.
"""

from __future__ import annotations

import ast
import os
from typing import Dict, List, Tuple

from .findings import Finding, Severity
from .analyzers.fail_open import FailOpenAnalyzer
from .analyzers.orphaned_tools import OrphanedToolAnalyzer
from .analyzers.eval_structure import EvalStructureAnalyzer
from .analyzers.secrets import SecretsAnalyzer
from .arabic.encoding_check import ArabicEncodingAnalyzer
from .arabic.numeral_check import ArabicNumeralAnalyzer

_SKIP_DIRS = {
    ".git", "__pycache__", ".venv", "venv", "env", "node_modules", "build",
    "dist", ".eggs", ".mypy_cache", ".pytest_cache", ".tox", "site-packages",
    ".idea", ".ruff_cache",
}


def _core_analyzers():
    return [FailOpenAnalyzer(), OrphanedToolAnalyzer(), EvalStructureAnalyzer(), SecretsAnalyzer()]


def _arabic_analyzers():
    return [ArabicEncodingAnalyzer(), ArabicNumeralAnalyzer()]


def iter_python_files(path: str):
    if os.path.isfile(path):
        if path.endswith(".py"):
            yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            if name.endswith(".py"):
                yield os.path.join(root, name)


class ScanResult:
    def __init__(self, findings: List[Finding], files_scanned: int, parse_errors: List[Tuple[str, str]]):
        self.findings = findings
        self.files_scanned = files_scanned
        self.parse_errors = parse_errors

    def counts(self) -> Dict[Severity, int]:
        out = {sev: 0 for sev in Severity}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def max_severity(self):
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.rank).severity


def scan(path: str, enable_arabic: bool = False) -> ScanResult:
    analyzers = _core_analyzers() + (_arabic_analyzers() if enable_arabic else [])
    findings: List[Finding] = []
    parse_errors: List[Tuple[str, str]] = []
    files = list(iter_python_files(path))

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                source = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            parse_errors.append((filepath, str(exc)))
            continue
        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError as exc:
            parse_errors.append((filepath, f"SyntaxError: {exc}"))
            continue
        for analyzer in analyzers:
            findings.extend(analyzer.check(tree, filepath, source))
            analyzer.collect(tree, filepath, source)

    for analyzer in analyzers:
        findings.extend(analyzer.finalize())

    findings.sort(key=lambda f: (-f.severity.rank, f.file, f.line, f.rule_id))
    return ScanResult(findings, len(files), parse_errors)
