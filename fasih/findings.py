"""Shared result types used by every analyzer.

Keeping these tiny and dependency-free means an analyzer is just a function
from (AST, source) -> list[Finding]; the engine and the reporters only ever
speak in terms of :class:`Finding` and :class:`Severity`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class Severity(Enum):
    """Ordered severity. Compare via :attr:`rank` (higher == more severe)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self.value]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls(value.lower())


@dataclass
class Finding:
    """A single issue at a specific location.

    ``why`` and ``fix`` are only surfaced in verbose output, so an analyzer
    can afford to make them genuinely explanatory.
    """

    rule_id: str
    severity: Severity
    message: str
    file: str
    line: int
    column: int = 0
    why: str = ""
    fix: str = ""
    snippet: str = ""

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "why": self.why,
            "fix": self.fix,
            "snippet": self.snippet,
        }
