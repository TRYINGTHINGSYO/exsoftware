from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .context import DEFAULT_MAX_BYTES
from .limits import RecursionLimits
from .models import Report
from .pipeline import analyze_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="exsoftware",
        description="Deterministic static analysis that explains a file. Does not execute it.",
    )
    parser.add_argument("--version", action="version", version=f"exsoftware {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a file and print a report")
    analyze.add_argument("path", type=Path, help="File to analyze")
    analyze.add_argument("--json", action="store_true", help="Write machine-readable JSON")
    analyze.add_argument("-o", "--output", type=Path, help="Write the report to a file")
    analyze.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="Max bytes fed to format analyzers")
    analyze.add_argument("--no-recurse", action="store_true", help="Do not recursively analyze ZIP members")
    analyze.add_argument("--max-depth", type=int, default=RecursionLimits.max_depth)
    analyze.add_argument("--max-members", type=int, default=RecursionLimits.max_member_count)
    analyze.add_argument("--max-expanded-bytes", type=int, default=RecursionLimits.max_total_expanded_bytes)
    analyze.add_argument("--max-member-bytes", type=int, default=RecursionLimits.max_member_bytes)
    analyze.add_argument("--max-ratio", type=float, default=RecursionLimits.max_compression_ratio)
    analyze.add_argument("--timeout", type=float, default=RecursionLimits.analyzer_timeout_seconds)

    serve = sub.add_parser("serve", help="Open the local report UI")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8745)
    serve.add_argument("--no-open", action="store_true", help="Do not open a browser")

    status = sub.add_parser(
        "security-status",
        help="Report analyzer containment capabilities (not a security score)",
    )
    status.add_argument("--json", action="store_true", help="Write JSON")

    args = parser.parse_args(argv)
    if args.command == "analyze":
        return _analyze(args)
    if args.command == "serve":
        return _serve(args)
    if args.command == "security-status":
        return _security_status(args)
    parser.error("unknown command")
    return 2


def _analyze(args: argparse.Namespace) -> int:
    path: Path = args.path
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    limits = RecursionLimits(
        enable_recursion=not args.no_recurse,
        max_depth=args.max_depth,
        max_member_count=args.max_members,
        max_total_expanded_bytes=args.max_expanded_bytes,
        max_member_bytes=args.max_member_bytes,
        max_compression_ratio=args.max_ratio,
        analyzer_timeout_seconds=args.timeout,
    )
    try:
        report = analyze_path(path, max_bytes=args.max_bytes, limits=limits)
    except Exception as exc:
        print(f"error: analysis failed: {exc}", file=sys.stderr)
        return 1
    payload = json.dumps(report.to_dict(), indent=2, default=str)
    text = render_text(report)
    if args.output:
        args.output.write_text(payload if args.json else text, encoding="utf-8")
    if args.json and not args.output:
        print(payload)
    elif not args.json:
        print(text)
    elif args.json and args.output:
        print(f"wrote {args.output}")
    return 0


def _serve(args: argparse.Namespace) -> int:
    from .api import run_server

    run_server(host=args.host, port=args.port, open_browser=not args.no_open)
    return 0


def _security_status(args: argparse.Namespace) -> int:
    from .isolate.status import format_status, inspect_isolation

    data = inspect_isolation()
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(format_status(data), end="")
    return 0


def render_text(report: Report) -> str:
    from .composition import render_text as render_composition

    return render_composition(report)
