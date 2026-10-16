"""Command-line interface for vulnscan."""

from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, pdf as pdf_mod
from .checks import run_checks
from .report import build_report, print_summary, write_html, write_json
from .scanner import DEFAULT_TIMEOUT, run_scan
from .targets import SpecError, parse_ports, parse_targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Network/service vulnerability scanner with HTML and JSON reports.")
    parser.add_argument("targets", nargs="+",
                        help="hostnames, IPs or CIDR ranges to scan")
    parser.add_argument("-p", "--ports", default=None,
                        help="port spec: 'top' (default), 'all', or e.g. "
                             "'22,80,8000-8100'")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"per-probe timeout in seconds (default {DEFAULT_TIMEOUT})")
    parser.add_argument("-c", "--concurrency", type=int, default=256,
                        help="max simultaneous probes (default 256)")
    parser.add_argument("--json", metavar="PATH", help="write JSON report to PATH")
    parser.add_argument("--html", metavar="PATH", help="write HTML report to PATH")
    parser.add_argument("--pdf", metavar="PATH", nargs="?", const="auto",
                        help="also render a PDF report; with no PATH it goes to "
                             "your Downloads folder automatically")
    parser.add_argument("--legacy-tls", action="store_true",
                        help="also test for TLS 1.0/1.1 support (slower)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress progress output")
    parser.add_argument("--no-color", action="store_true",
                        help="disable colored terminal output")
    parser.add_argument("--version", action="version",
                        version=f"vulnscan {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        hosts = parse_targets(args.targets)
        ports = parse_ports(args.ports)
    except SpecError as exc:
        print(f"vulnscan: {exc}", file=sys.stderr)
        return 2

    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    start = time.monotonic()

    def progress(done: int, total: int, result) -> None:
        if not args.quiet:
            sys.stderr.write(f"\r  probing {done}/{total} "
                             f"(open: {result.host}:{result.port})   ")
            sys.stderr.flush()

    if not args.quiet:
        print(f"vulnscan {__version__} — {len(hosts)} target(s), {len(ports)} port(s)")

    services = asyncio.run(run_scan(hosts, ports, timeout=args.timeout,
                                    concurrency=args.concurrency,
                                    progress=progress if not args.quiet else None))
    if not args.quiet:
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()

    findings = asyncio.run(run_checks(services, args.timeout,
                                      check_legacy_tls=args.legacy_tls))
    duration = time.monotonic() - start

    report = build_report(
        targets=hosts, ports=ports, services=services, findings=findings,
        started_at=started_at, duration_s=duration,
        options={"timeout": args.timeout, "concurrency": args.concurrency,
                 "legacy_tls_check": args.legacy_tls})

    color = sys.stdout.isatty() and not args.no_color
    print_summary(report, color=color)

    written = []
    if args.json:
        write_json(report, args.json)
        written.append(args.json)
    html_path = args.html
    if args.pdf is not None and not html_path:
        html_path = os.path.join("out", "report.html")   # required for rendering
    if html_path:
        write_html(report, html_path)
        written.append(html_path)
    if args.pdf is not None:
        target = (pdf_mod.default_pdf_path()
                  if args.pdf == "auto" else Path(args.pdf))
        try:
            pdf_path = pdf_mod.html_to_pdf(Path(html_path), target)
            written.append(str(pdf_path))
        except (RuntimeError, subprocess.SubprocessError) as exc:
            print(f"vulnscan: PDF rendering failed: {exc}", file=sys.stderr)
    for path in written:
        print(f"  report written to {path}")
    if written:
        print()

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
