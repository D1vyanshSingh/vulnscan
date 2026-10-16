"""Automatic PDF report rendering via a locally installed browser engine.

Converted with headless Microsoft Edge (or Chrome) when Edge is absent, so the
PDF is a pixel-faithful render of the styled HTML report with no extra
pip packages. Falls back gracefully and reports clearly if no browser exists.
"""

from __future__ import annotations

import datetime as _dt
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

_EDGE_PATHS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/microsoft-edge",
    "/usr/bin/microsoft-edge-stable",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
]
_CHROME_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def find_browser() -> str | None:
    """Return an absolute browser path capable of --headless --print-to-pdf."""
    for candidate in _EDGE_PATHS + _CHROME_PATHS:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    for name in ("msedge", "chrome", "chromium"):
        found = shutil.which(name)
        if found:
            return found
    return None


def default_pdf_path() -> Path:
    """Timestamped filename in the user's Downloads folder."""
    home = Path.home()
    downloads = home / "Downloads"
    if not downloads.is_dir():                 # linux/mac layouts differ
        downloads = home / "Desktop"
        if not downloads.is_dir():
            downloads = home
    stamp = _dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    return downloads / f"vulnscan-report_{stamp}.pdf"


def html_to_pdf(html_path: Path, pdf_path: Path, timeout_s: float = 60.0) -> Path:
    """Render an HTML report file to PDF; returns the written PDF path."""
    browser = find_browser()
    if not browser:
        raise RuntimeError(
            "No Microsoft Edge or Chrome installation found — install Edge or "
            "pass --html and print it manually.")
    html_path = Path(html_path).resolve()
    pdf_path = Path(pdf_path).resolve()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    # Edge/Chrome accept plain file:// URIs even with spaces in the path.
    file_url = html_path.as_uri()
    command = [
        browser,
        "--headless", "--disable-gpu", "--no-pdf-header-footer",
        "--disable-extensions", "--disable-crash-reporter",
        f"--print-to-pdf={pdf_path}",
        file_url,
    ]
    proc = subprocess.run(command, capture_output=True, timeout=timeout_s)
    # Headless Edge may exit while the writer finishes asynchronously.
    deadline = time.monotonic() + 15.0
    while not pdf_path.exists() and time.monotonic() < deadline:
        time.sleep(0.25)
    if not pdf_path.exists():
        raise RuntimeError(
            f"PDF rendering failed (exit {proc.returncode}): "
            f"{(proc.stderr or proc.stdout or b'').decode('utf-8', 'replace')[:300]}")
    return pdf_path
