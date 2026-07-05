"""Shared result types used by every analyzer.

Keeping these tiny and dependency-free means an analyzer is just a function
from (AST, source) -> list[Finding]; the engine and the reporters only ever
speak in terms of :class:`Finding` and :class:`Severity`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

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
    # Optional auto-fix: replace source bytes [fix_start, fix_end) with
    # fix_replacement. Byte offsets, because ast column offsets are byte-based.
    fix_start: Optional[int] = None
    fix_end: Optional[int] = None
    fix_replacement: Optional[str] = None

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    @property
    def fixable(self) -> bool:
        return self.fix_start is not None and self.fix_replacement is not None

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
            "fixable": self.fixable,
        }
