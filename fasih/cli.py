"""Command-line entry point: ``fasih scan <path> [options]``."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__, report
from .findings import Severity
from .rules_engine import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fasih",
        description="Lint LLM agents/pipelines for reliability and Arabic/bilingual bugs.",
    )
    parser.add_argument("--version", action="version", version=f"fasih {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a file or directory.")
    scan_p.add_argument("path", help="File or directory to scan.")
    scan_p.add_argument("--arabic", action="store_true", help="Also run Arabic/bilingual pipeline checks.")
    scan_p.add_argument("-v", "--verbose", action="store_true", help="Show why-it-matters and fix hints.")
    scan_p.add_argument(
        "--format", choices=["terminal", "markdown", "json"], default="terminal", help="Output format."
    )
    scan_p.add_argument("--out", metavar="FILE", help="Write the report to FILE instead of stdout.")
    scan_p.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default=None,
        help="Exit non-zero if any finding at this severity or higher is present (for CI).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    result = scan(args.path, enable_arabic=args.arabic)

    if args.format == "json":
        output = report.render_json(result)
    elif args.format == "markdown":
        output = report.render_markdown(result)
    elif args.out:
        output = report.render_plain(result, verbose=args.verbose)
    else:
        report.render_terminal(result, verbose=args.verbose)
        output = None

    if output is not None:
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(output if output.endswith("\n") else output + "\n")
            print(f"Wrote report to {args.out}")
        else:
            print(output)

    if args.fail_on:
        threshold = Severity.from_str(args.fail_on)
        if any(f.severity.rank >= threshold.rank for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
