"""Persistent user configuration for vulnscan.

Stored as JSON in ~/.vulnscan/config.json (overridable via the
VULNSCAN_CONFIG_DIR environment variable). Only known keys are honored, so
hand-edited files can't inject unexpected settings.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("VULNSCAN_CONFIG_DIR")
                  or Path.home() / ".vulnscan")
CONFIG_PATH = CONFIG_DIR / "config.json"

# None means "use the built-in default" (out/ for HTML+JSON, Downloads for PDF).
DEFAULTS: dict[str, str | None] = {
    "output_dir": None,
    "pdf_dir": None,
}

_KEYS = frozenset(DEFAULTS)


def load_config() -> dict[str, str | None]:
    """Load the saved config, falling back to defaults on any problem."""
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(DEFAULTS)
    if not isinstance(data, dict):
        return dict(DEFAULTS)
    return {**DEFAULTS, **{k: v for k, v in data.items() if k in _KEYS
                           and isinstance(v, (str, type(None)))}}


def save_config(config: dict[str, str | None]) -> None:
    """Persist the config to disk (creates the config directory if needed)."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(
        json.dumps(config, indent=2) + "\n", encoding="utf-8")
