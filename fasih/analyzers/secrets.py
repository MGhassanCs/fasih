"""HARDCODED-SECRET — credentials committed into source.

Two layers:

* **Provider keys** (regex over raw source): distinctive, high-entropy tokens
  with known prefixes (OpenAI, Anthropic, AWS, Google, GitHub, Slack, Stripe,
  SendGrid) and PEM private-key blocks. These are almost never false positives,
  so they are reported at CRITICAL. The patterns are written with character
  classes so this file does not match *itself* when fasih scans its own source.

* **Generic assignments** (AST): a ``name = "literal"`` where the name looks
  like a secret (``api_key``, ``password``, ``token`` …) and the literal is a
  plausible secret value (long enough, no spaces, not an obvious placeholder).
  Doing this on the AST rather than by regex avoids matching env lookups
  (``os.environ[...]`` is not a string constant) and keeps precision high.
  Reported at HIGH.

The finding never echoes the secret value itself.
"""

from __future__ import annotations

import ast
import re
from typing import Iterable, List

from ..findings import Finding, Severity

_PROVIDER_PATTERNS = [
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Stripe secret key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{16,}\b")),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
]

_SECRET_NAME_RE = re.compile(
    r"(secret|token|passwd|password|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|credential)",
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(
    r"your[-_ ]?|example|changeme|change_me|placeholder|dummy|xxx+|redacted|"
    r"<[^>]+>|\{[^}]*\}|\.\.\.|todo|fixme|test[-_]?key|fake|sample|^none$|^null$",
    re.IGNORECASE,
)


class SecretsAnalyzer:
    """Not an :class:`Analyzer` subclass by inheritance only to keep this file
    import-light; it implements the same ``check`` interface the engine calls.
    """

    rule_id = "HARDCODED-SECRET"

    def check(self, tree: ast.AST, filename: str, source: str) -> Iterable[Finding]:
        provider = self._provider_keys(filename, source)
        flagged_lines = {f.line for f in provider}
        generic = [f for f in self._generic_assignments(tree, filename, source) if f.line not in flagged_lines]
        return provider + generic

    def collect(self, tree, filename, source):  # no whole-project state
        return None

    def finalize(self):
        return []

    # -- provider keys -------------------------------------------------------

    def _provider_keys(self, filename: str, source: str) -> List[Finding]:
        findings: List[Finding] = []
        for i, line in enumerate(source.splitlines(), start=1):
            for label, pattern in _PROVIDER_PATTERNS:
                match = pattern.search(line)
                if match:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.CRITICAL,
                            message=f"Possible hardcoded {label} committed in source.",
                            file=filename,
                            line=i,
                            column=match.start(),
                            why=(
                                "A committed credential lives in git history forever, even "
                                "after you delete the line. Anyone with repo access — the "
                                "whole internet, if the repo is public — can extract and "
                                "use it."
                            ),
                            fix=(
                                "Load it from an environment variable or secret manager at "
                                "runtime and rotate the exposed key immediately."
                            ),
                            snippet="<redacted>",
                        )
                    )
                    break  # at most one provider finding per line
        return findings

    # -- generic assignments -------------------------------------------------

    def _generic_assignments(self, tree: ast.AST, filename: str, source: str) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            else:
                continue
            if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
                continue
            literal = value.value
            for target in targets:
                name = self._target_name(target)
                if not name or not _SECRET_NAME_RE.search(name):
                    continue
                if self._is_placeholder(literal):
                    continue
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        message=f"`{name}` is assigned a hardcoded secret literal.",
                        file=filename,
                        line=node.lineno,
                        column=node.col_offset,
                        why=(
                            "A secret in source is committed to git history and shipped to "
                            "anyone who can read the repo. Config like this belongs in the "
                            "environment, not the codebase."
                        ),
                        fix="Read it from os.environ / a secret manager at runtime, and rotate it.",
                        snippet="<redacted>",
                    )
                )
                break
        return findings

    @staticmethod
    def _target_name(target: ast.AST) -> str:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        return ""

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        if len(value) < 12 or " " in value:
            return True
        if _PLACEHOLDER_RE.search(value):
            return True
        # Require a bit of entropy: a real secret is not a single lowercase word.
        has_digit = any(c.isdigit() for c in value)
        has_symbol = any(not c.isalnum() and c not in "_-" for c in value)
        if len(value) >= 20 or has_digit or has_symbol:
            return False
        return True
