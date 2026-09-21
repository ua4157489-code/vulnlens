"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from vulnlens import __version__
from vulnlens.collectors import ParseError, detect_collector, get_collector
from vulnlens.core.models import Severity
from vulnlens.reporting import render_summary, to_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnlens",
        description="Aggregate and normalize vulnerability scan results.",
        epilog="Only analyze scan data from systems you are authorized to assess.",
    )
    parser.add_argument("--version", action="version", version=f"vulnlens {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    parse = sub.add_parser("parse", help="Parse a scan file; print a summary or export JSON")
    parse.add_argument("file", type=Path, help="Nmap (-oX) or OpenVAS XML report")
    parse.add_argument(
        "-f", "--format", default="auto", choices=["auto", "nmap", "openvas"],
        help="Input format (default: auto-detect)",
    )
    parse.add_argument(
        "-m", "--min-severity", default="info",
        choices=[s.name.lower() for s in Severity], help="Hide findings below this level",
    )
    parse.add_argument("-o", "--output", type=Path, help="Write normalized JSON to this file")
    parse.set_defaults(func=cmd_parse)
    return parser


def cmd_parse(args: argparse.Namespace) -> int:
    collector = detect_collector(args.file) if args.format == "auto" else get_collector(args.format)
    result = collector.parse(args.file).filter_min_severity(Severity.from_name(args.min_severity))

    if args.output:
        args.output.write_text(to_json(result), encoding="utf-8")
        print(f"Wrote {len(result.findings)} findings to {args.output}")
    else:
        print(render_summary(result))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
