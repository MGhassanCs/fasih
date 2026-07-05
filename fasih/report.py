"""Render a :class:`ScanResult` as a rich terminal report, markdown, or JSON."""

from __future__ import annotations

import json
import os
from typing import List

from .findings import Finding, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}
_SEV_LABEL = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED",
    Severity.LOW: "LOW",
}


def _rel(path: str) -> str:
    try:
        return os.path.relpath(path)
    except ValueError:
        return path


def _summary_text(result) -> str:
    counts = result.counts()
    parts = [f"{counts[s]} {s.value}" for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW) if counts[s]]
    tail = ", ".join(parts) if parts else "none"
    return f"{len(result.findings)} finding(s) across {result.files_scanned} file(s): {tail}"


# --- terminal (rich) --------------------------------------------------------

def render_terminal(result, verbose: bool = False) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text

    console = Console()
    console.print()
    console.print(Text("fasih", style="bold") + Text(" — agent reliability scan", style="dim"))
    console.print()

    if not result.findings:
        console.print(Panel.fit(Text("No issues found. ✓", style="bold green"), border_style="green"))
        console.print(Text(_summary_text(result), style="dim"))
        _print_parse_errors(console, result)
        return

    if verbose:
        for f in result.findings:
            _print_verbose(console, f)
    else:
        for f in result.findings:
            header = Text()
            header.append(f" {_SEV_LABEL[f.severity]:^4} ", style=_SEV_STYLE[f.severity])
            header.append("  ")
            header.append(f.rule_id, style="bold")
            header.append("  ")
            header.append(f"{_rel(f.file)}:{f.line}", style="cyan")
            console.print(header)
            console.print(Text("       " + f.message, style="default"))
            console.print()

    console.print(Text(_summary_text(result), style="dim"))
    _print_parse_errors(console, result)


def _print_verbose(console, f: Finding) -> None:
    from rich.panel import Panel
    from rich.text import Text

    body = Text()
    body.append(f.message + "\n\n")
    if f.snippet and f.snippet != "<redacted>":
        body.append("    " + f.snippet + "\n\n", style="dim")
    if f.why:
        body.append("Why: ", style="bold")
        body.append(f.why + "\n\n")
    if f.fix:
        body.append("Fix: ", style="bold")
        body.append(f.fix)
    title = Text(f"{_SEV_LABEL[f.severity]}  {f.rule_id}  ", style=_SEV_STYLE[f.severity])
    title.append(f"{_rel(f.file)}:{f.line}", style="cyan")
    console.print(Panel(body, title=title, title_align="left", border_style=_SEV_STYLE[f.severity]))


def _print_parse_errors(console, result) -> None:
    if result.parse_errors:
        from rich.text import Text

        console.print(Text(f"({len(result.parse_errors)} file(s) skipped — could not parse)", style="dim yellow"))


# --- plain text (for --out with terminal format) ----------------------------

def render_plain(result, verbose: bool = False) -> str:
    lines = ["fasih — agent reliability scan", _summary_text(result), ""]
    if not result.findings:
        lines.append("No issues found.")
        return "\n".join(lines)
    for f in result.findings:
        lines.append(f"[{_SEV_LABEL[f.severity]}] {f.rule_id}  {_rel(f.file)}:{f.line}")
        lines.append(f"    {f.message}")
        if verbose:
            if f.why:
                lines.append(f"    Why: {f.why}")
            if f.fix:
                lines.append(f"    Fix: {f.fix}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# --- markdown ---------------------------------------------------------------

def render_markdown(result) -> str:
    counts = result.counts()
    lines: List[str] = ["# fasih report", ""]
    lines.append(f"**{_summary_text(result)}**")
    lines.append("")
    if result.findings:
        lines.append("| Severity | Rule | Location | Issue |")
        lines.append("| --- | --- | --- | --- |")
        for f in result.findings:
            issue = f.message.replace("|", "\\|")
            lines.append(f"| {_SEV_LABEL[f.severity]} | `{f.rule_id}` | `{_rel(f.file)}:{f.line}` | {issue} |")
        lines.append("")
        for f in result.findings:
            lines.append(f"### `{f.rule_id}` — {_SEV_LABEL[f.severity]} — `{_rel(f.file)}:{f.line}`")
            lines.append("")
            lines.append(f.message)
            if f.snippet and f.snippet != "<redacted>":
                lines.append("")
                lines.append("```python")
                lines.append(f.snippet)
                lines.append("```")
            if f.why:
                lines.append("")
                lines.append(f"**Why it matters:** {f.why}")
            if f.fix:
                lines.append("")
                lines.append(f"**Fix:** {f.fix}")
            lines.append("")
    else:
        lines.append("No issues found. ✓")
        lines.append("")
    return "\n".join(lines)


# --- json -------------------------------------------------------------------

def render_json(result) -> str:
    payload = {
        "files_scanned": result.files_scanned,
        "summary": {s.value: result.counts()[s] for s in Severity},
        "findings": [f.to_dict() for f in result.findings],
        "parse_errors": [{"file": p, "error": e} for p, e in result.parse_errors],
    }
    # We eat our own dog food: ensure_ascii=False so Arabic in snippets is readable.
    return json.dumps(payload, indent=2, ensure_ascii=False)
