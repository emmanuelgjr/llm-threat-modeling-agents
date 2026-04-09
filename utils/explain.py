"""``threat-model --explain <Name>`` reference lookup.

Surfaces the COMPASS threat / MAESTRO layer metadata as a small CLI help
panel so users don't have to grep the source.
"""

from __future__ import annotations

import difflib

from utils.compass_threats import COMPASS_THREATS
from utils.maestro_layers import MAESTRO_LAYERS


def explain(name: str) -> str:
    if name in COMPASS_THREATS:
        return _format_threat(name, COMPASS_THREATS[name])
    if name in MAESTRO_LAYERS:
        return _format_layer(name, MAESTRO_LAYERS[name])

    candidates = list(COMPASS_THREATS) + list(MAESTRO_LAYERS)
    suggestions = difflib.get_close_matches(name, candidates, n=3, cutoff=0.4)
    msg = [f"No threat or layer named '{name}'."]
    if suggestions:
        msg.append("Did you mean: " + ", ".join(suggestions) + "?")
    msg.append("\nKnown COMPASS threats:")
    msg.extend(f"  - {t}" for t in COMPASS_THREATS)
    msg.append("\nKnown MAESTRO layers:")
    msg.extend(f"  - {l}" for l in MAESTRO_LAYERS)
    return "\n".join(msg)


def _format_threat(name: str, meta: dict) -> str:
    lines = [
        f"COMPASS Threat: {name}",
        "=" * (16 + len(name)),
        f"Impact         : {meta.get('impact', '?')} / 5",
        f"MAESTRO layers : {', '.join(meta.get('maestro_layers', [])) or '-'}",
        f"CWEs           : {', '.join(meta.get('cwes', [])) or '-'}",
        f"Indicators     : {', '.join(meta.get('indicators', [])) or '-'}",
        "",
        "Mitigation:",
        f"  {meta.get('mitigation', '-')}",
    ]
    return "\n".join(lines)


def _format_layer(name: str, meta: dict) -> str:
    lines = [
        f"MAESTRO Layer: {name}",
        "=" * (15 + len(name)),
        f"Description : {meta.get('description', '-')}",
        f"Indicators  : {', '.join(meta.get('indicators', [])) or '-'}",
    ]
    return "\n".join(lines)
