"""AR-ENCODING — ``json.dumps`` without ``ensure_ascii=False`` mangles Arabic.

Python's ``json`` defaults to ``ensure_ascii=True``, so any non-ASCII text —
all Arabic — is emitted as ``\\uXXXX`` escape sequences. That is technically
valid JSON, but it breaks the moment a downstream system, webhook, WhatsApp
payload, log line, or saved ``.json`` file is read by a human or by anything
that does a naive string comparison. The fix is one keyword argument, and this
rule exists because it is forgotten constantly in bilingual pipelines.

We track how ``json`` is imported (``import json``, ``import json as j``,
``from json import dumps``) so the common call forms are all caught, and we do
not flag a call that already passes ``ensure_ascii=False`` or spreads
``**kwargs`` (where we cannot know).
"""

from __future__ import annotations

import ast
from typing import Iterable, List

from ..findings import Finding, Severity
from ..analyzers.base import Analyzer, source_line


class ArabicEncodingAnalyzer(Analyzer):
    rule_id = "AR-ENCODING"

    def check(self, tree: ast.AST, filename: str, source: str) -> Iterable[Finding]:
        json_aliases = {"json"}
        dumps_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "json":
                        json_aliases.add(alias.asname or "json")
            elif isinstance(node, ast.ImportFrom) and node.module == "json":
                for alias in node.names:
                    if alias.name in ("dumps", "dump"):
                        dumps_names.add(alias.asname or alias.name)

        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not self._is_json_dumps(node.func, json_aliases, dumps_names):
                continue
            if self._is_safe(node):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.MEDIUM,
                    message=(
                        "json.dumps()/dump() without ensure_ascii=False will escape "
                        "Arabic text to \\uXXXX."
                    ),
                    file=filename,
                    line=node.lineno,
                    column=node.col_offset,
                    why=(
                        "ensure_ascii defaults to True, so Arabic is serialized as \\uXXXX "
                        "escapes. Downstream systems, webhooks, WhatsApp payloads and saved "
                        "files then carry mangled, unreadable Arabic — or break on it."
                    ),
                    fix="Pass ensure_ascii=False to json.dumps / json.dump.",
                    snippet=source_line(source, node.lineno),
                )
            )
        return findings

    @staticmethod
    def _is_json_dumps(func: ast.AST, json_aliases, dumps_names) -> bool:
        if isinstance(func, ast.Attribute) and func.attr in ("dumps", "dump"):
            return isinstance(func.value, ast.Name) and func.value.id in json_aliases
        if isinstance(func, ast.Name):
            return func.id in dumps_names
        return False

    @staticmethod
    def _is_safe(call: ast.Call) -> bool:
        for kw in call.keywords:
            if kw.arg is None:
                return True  # **kwargs spread — cannot prove it's wrong, don't flag
            if kw.arg == "ensure_ascii":
                return isinstance(kw.value, ast.Constant) and kw.value.value is False
        return False
