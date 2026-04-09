"""Project-level config file (``threat-model.toml``).

Lets users pin defaults so CI invocations don't need long flag lists. Reads
the file with stdlib ``tomllib`` (3.11+) or ``tomli`` if installed; if no
TOML parser is available we silently fall back to flag-only mode.

Example ``threat-model.toml``::

    [defaults]
    input = "data/sample_inputs.json"
    output = "output/results.json"
    markdown = "output/report.md"
    html = "output/report.html"
    sarif = "output/results.sarif"
    history = "output/history.jsonl"
    fail_on = "high"
    plugins = ["data/plugins"]
"""

from __future__ import annotations

import os
from typing import Any

DEFAULT_FILENAMES = ("threat-model.toml", ".threat-model.toml")


def _load_toml(path: str) -> dict:
    try:
        import tomllib  # type: ignore
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def find_config(start_dir: str | None = None) -> str | None:
    cwd = start_dir or os.getcwd()
    for name in DEFAULT_FILENAMES:
        candidate = os.path.join(cwd, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def load_defaults(path: str | None = None) -> dict[str, Any]:
    if path is None:
        path = find_config()
    if not path or not os.path.isfile(path):
        return {}
    data = _load_toml(path)
    return data.get("defaults", {}) or {}
