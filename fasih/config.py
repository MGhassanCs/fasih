"""Optional configuration from ``pyproject.toml [tool.fasih]`` or ``.fasih.toml``.

Discovered by walking up from the scanned path. Keys (all optional):

    [tool.fasih]
    arabic = true                 # enable the Arabic module by default
    fail_on = "high"              # default CI threshold
    disable = ["AR-BIDI"]         # rule ids to turn off
    ignore = ["**/migrations/*", "vendor/*"]   # path globs to skip

TOML is parsed with the standard-library ``tomllib`` (Python 3.11+) or the
``tomli`` backport on older versions. Parsing is data-only — no code execution.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import List, Optional, Set

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - depends on interpreter version
    try:
        import tomli as _toml
    except ModuleNotFoundError:
        _toml = None


@dataclass
class Config:
    ignore: List[str] = field(default_factory=list)
    disable: Set[str] = field(default_factory=set)
    arabic: Optional[bool] = None
    fail_on: Optional[str] = None
    source: Optional[str] = None

    def is_ignored(self, path: str) -> bool:
        norm = path.replace(os.sep, "/")
        base = os.path.basename(norm)
        return any(fnmatch(norm, pat) or fnmatch(base, pat) for pat in self.ignore)

    def allows(self, rule_id: str) -> bool:
        return rule_id not in self.disable


def _from_table(table: dict, source: str) -> Config:
    arabic = table.get("arabic")
    fail_on = table.get("fail_on")
    return Config(
        ignore=[str(p) for p in (table.get("ignore") or [])],
        disable={str(r) for r in (table.get("disable") or [])},
        arabic=arabic if isinstance(arabic, bool) else None,
        fail_on=fail_on if isinstance(fail_on, str) else None,
        source=source,
    )


def load_config(start_path: str) -> Config:
    """Find the nearest config by walking up from ``start_path``. Returns an
    empty :class:`Config` if none is found (or TOML support is unavailable)."""
    if _toml is None:
        return Config()
    directory = os.path.abspath(start_path if os.path.isdir(start_path) else os.path.dirname(start_path) or ".")
    while True:
        dotfile = os.path.join(directory, ".fasih.toml")
        if os.path.isfile(dotfile):
            with open(dotfile, "rb") as fh:
                data = _toml.load(fh)
            return _from_table(data.get("fasih", data), dotfile)

        pyproject = os.path.join(directory, "pyproject.toml")
        if os.path.isfile(pyproject):
            with open(pyproject, "rb") as fh:
                data = _toml.load(fh)
            table = data.get("tool", {}).get("fasih")
            if table is not None:
                return _from_table(table, pyproject)

        parent = os.path.dirname(directory)
        if parent == directory:
            return Config()
        directory = parent
