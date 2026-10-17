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
    parser.add_argument("-o", "--output-dir", metavar="DIR", default="out",
                        help="directory for the automatic HTML/JSON reports "
                             "(default: out)")
    parser.add_argument("-c", "--concurrency", type=int, default=256,
                        help="max simultaneous probes (default 256)")
    parser.add_argument("--json", metavar="PATH", nargs="?", const="auto",
                        help="write JSON report to PATH (default: automatic)")
    parser.add_argument("--html", metavar="PATH", nargs="?", const="auto",
                        help="write HTML report to PATH (default: automatic)")
    parser.add_argument("--pdf", metavar="PATH", nargs="?", const="auto",
                        help="render a PDF report; with no PATH it goes to your "
                             "Downloads folder automatically (default: automatic)")
    parser.add_argument("--no-html", action="store_true",
                        help="skip the automatic HTML report")
    parser.add_argument("--no-json", action="store_true",
                        help="skip the automatic JSON report")
    parser.add_argument("--no-pdf", action="store_true",
                        help="skip the automatic PDF report")
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

    # Reports are automatic by default: report files land in the output
    # directory (default out/), the PDF in Downloads. Explicit paths override;
    # --no-* flags opt out.
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    out_dir = args.output_dir
    written = []
    json_path = None if args.no_json else (
        args.json if args.json else os.path.join(out_dir, f"vulnscan-report_{stamp}.json"))
    html_path = None if args.no_html else (
        args.html if args.html else os.path.join(out_dir, f"vulnscan-report_{stamp}.html"))
    if json_path == "auto":
        json_path = os.path.join(out_dir, f"vulnscan-report_{stamp}.json")
    if html_path == "auto":
        html_path = os.path.join(out_dir, f"vulnscan-report_{stamp}.html")
    if json_path:
        os.makedirs(os.path.dirname(json_path) or ".", exist_ok=True)
        write_json(report, json_path)
        written.append(json_path)
    if html_path:
        os.makedirs(os.path.dirname(html_path) or ".", exist_ok=True)
        write_html(report, html_path)
        written.append(html_path)
    wants_pdf = (not args.no_pdf) if args.pdf is None else (args.pdf is not None)
    if wants_pdf and html_path:
        target = (pdf_mod.default_pdf_path()
                  if args.pdf in (None, "auto") else Path(args.pdf))
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
