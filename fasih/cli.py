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
    scan_p.add_argument("path", nargs="+", help="One or more files or directories to scan.")
    scan_p.add_argument("--arabic", action="store_true", help="Also run Arabic/bilingual pipeline checks.")
    scan_p.add_argument("-v", "--verbose", action="store_true", help="Show why-it-matters and fix hints.")
    scan_p.add_argument(
        "--format", choices=["terminal", "markdown", "json"], default="terminal", help="Output format."
    )
    scan_p.add_argument("--out", metavar="FILE", help="Write the report to FILE instead of stdout.")
    scan_p.add_argument("--fix", action="store_true", help="Apply the safe auto-fixes to files in place.")
    scan_p.add_argument("--diff", action="store_true", help="Show the auto-fix diff without writing anything.")
    scan_p.add_argument("--no-config", action="store_true", help="Ignore any pyproject.toml/.fasih.toml config.")
    scan_p.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default=None,
        help="Exit non-zero if any finding at this severity or higher is present (for CI).",
    )

    serve_p = sub.add_parser("serve", help="Launch a local web dashboard (stdlib only).")
    serve_p.add_argument("--port", type=int, default=8787, help="Port (default 8787).")
    serve_p.add_argument("--host", default="127.0.0.1", help="Bind host (default localhost only).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        from .web import serve

        serve(host=args.host, port=args.port)
        return 0

    if args.command != "scan":
        parser.print_help()
        return 2

    from .config import Config, load_config

    config = Config() if args.no_config else load_config(args.path[0])
    enable_arabic = args.arabic or bool(config.arabic)
    fail_on = args.fail_on or config.fail_on

    result = scan(args.path, enable_arabic=enable_arabic, config=config)

    if args.diff or args.fix:
        from . import fixes

        by_file = {}
        for finding in result.findings:
            if finding.fixable:
                by_file.setdefault(finding.file, []).append(finding)

        if args.diff:
            shown = False
            for path in sorted(by_file):
                diff = fixes.preview_file(path, by_file[path])
                if diff:
                    print(diff, end="" if diff.endswith("\n") else "\n")
                    shown = True
            if not shown:
                print("No auto-fixable findings.")
            return 0

        applied, files_fixed, skipped = 0, 0, []
        for path in sorted(by_file):
            count = fixes.apply_file(path, by_file[path])
            if count > 0:
                applied += count
                files_fixed += 1
            elif count < 0:
                skipped.append(path)
        print(f"Applied {applied} auto-fix(es) across {files_fixed} file(s).")
        for path in skipped:
            print(f"  skipped {path} (fix would not re-parse)")
        result = scan(args.path, enable_arabic=enable_arabic, config=config)  # re-scan to show what remains

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

    if fail_on:
        threshold = Severity.from_str(fail_on)
        if any(f.severity.rank >= threshold.rank for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
