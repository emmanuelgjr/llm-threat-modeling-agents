"""Custom threat / layer plugin loader.

Lets users extend the framework with their own MAESTRO layers and COMPASS
threats by dropping JSON files in a directory — no code edits, no Python
imports, no extra dependencies.

Plugin file format::

    {
      "maestro_layers": {
        "Network": {
          "description": "...",
          "indicators": ["network", "firewall"]
        }
      },
      "compass_threats": {
        "Custom Threat Name": {
          "indicators": ["foo", "bar"],
          "maestro_layers": ["Network"],
          "impact": 4,
          "cwes": ["CWE-200"],
          "mitigation": "Do the thing."
        }
      }
    }

Files can declare either or both sections; missing fields are filled with
sensible defaults so a minimal plugin is just a name + indicators.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Iterable

from utils.compass_threats import COMPASS_THREATS
from utils.maestro_layers import MAESTRO_LAYERS

logger = logging.getLogger(__name__)


class PluginError(ValueError):
    pass


_LAYER_DEFAULTS = {"description": "", "indicators": []}
_THREAT_DEFAULTS = {
    "indicators": [],
    "maestro_layers": [],
    "impact": 3,
    "cwes": [],
    "mitigation": "",
}


def _validate_layer(name: str, data: dict) -> dict:
    if not isinstance(data, dict):
        raise PluginError(f"Layer '{name}' must be an object.")
    merged = {**_LAYER_DEFAULTS, **data}
    if not isinstance(merged["indicators"], list):
        raise PluginError(f"Layer '{name}'.indicators must be a list.")
    return merged


def _validate_threat(name: str, data: dict) -> dict:
    if not isinstance(data, dict):
        raise PluginError(f"Threat '{name}' must be an object.")
    merged = {**_THREAT_DEFAULTS, **data}
    if not isinstance(merged["indicators"], list):
        raise PluginError(f"Threat '{name}'.indicators must be a list.")
    if not isinstance(merged["maestro_layers"], list):
        raise PluginError(f"Threat '{name}'.maestro_layers must be a list.")
    if not isinstance(merged["cwes"], list):
        raise PluginError(f"Threat '{name}'.cwes must be a list.")
    try:
        merged["impact"] = int(merged["impact"])
    except (TypeError, ValueError) as exc:
        raise PluginError(f"Threat '{name}'.impact must be int 1-5.") from exc
    if not 1 <= merged["impact"] <= 5:
        raise PluginError(f"Threat '{name}'.impact must be 1-5.")
    return merged


def load_plugin_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            raise PluginError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PluginError(f"{path}: top-level must be an object.")
    return data


def discover_plugin_files(directory: str) -> list[str]:
    if not os.path.isdir(directory):
        return []
    return sorted(
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if f.endswith(".json") and not f.startswith("_")
    )


def load_plugins(sources: Iterable[str]) -> dict:
    """Load and merge plugins.

    ``sources`` may contain file paths or directories. Returns a dict with
    aggregated ``maestro_layers`` and ``compass_threats`` for inspection.
    The function also mutates the global registries in-place so subsequently
    instantiated agents pick up the additions.
    """
    added_layers: dict = {}
    added_threats: dict = {}

    paths: list[str] = []
    for source in sources:
        if os.path.isdir(source):
            paths.extend(discover_plugin_files(source))
        else:
            paths.append(source)

    for path in paths:
        data = load_plugin_file(path)
        for name, raw in (data.get("maestro_layers") or {}).items():
            layer = _validate_layer(name, raw)
            MAESTRO_LAYERS[name] = layer
            added_layers[name] = layer
        for name, raw in (data.get("compass_threats") or {}).items():
            threat = _validate_threat(name, raw)
            # Validate referenced layers exist (after layer additions).
            unknown = [l for l in threat["maestro_layers"] if l not in MAESTRO_LAYERS]
            if unknown:
                raise PluginError(
                    f"Threat '{name}' references unknown MAESTRO layers: {unknown}"
                )
            COMPASS_THREATS[name] = threat
            added_threats[name] = threat
        logger.info(
            "Loaded plugin %s: +%d layers, +%d threats",
            path,
            len(data.get("maestro_layers") or {}),
            len(data.get("compass_threats") or {}),
        )

    return {"maestro_layers": added_layers, "compass_threats": added_threats}
