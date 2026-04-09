"""Custom risk-scoring overrides loaded from plugin files.

A plugin can declare a ``scoring`` section to extend the per-environment
likelihood boost map used by ``RiskAnalyzer``::

    {
      "scoring": {
        "environment_boost": {
          "iot": 1,
          "industrial": 2
        }
      }
    }

Boosts are merged (max wins) into a global registry that ``main.py`` reads
when constructing the analyzer.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Iterable

from utils.plugins import discover_plugin_files

logger = logging.getLogger(__name__)

ENV_BOOST: dict[str, int] = {}


def reset() -> None:
    ENV_BOOST.clear()


def load_scoring_plugins(sources: Iterable[str]) -> dict:
    """Merge ``scoring.environment_boost`` from one or more plugin files."""
    paths: list[str] = []
    for source in sources or []:
        if os.path.isdir(source):
            paths.extend(discover_plugin_files(source))
        elif os.path.isfile(source):
            paths.append(source)

    added: dict[str, int] = {}
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        section = ((data.get("scoring") or {}).get("environment_boost")) or {}
        for env, boost in section.items():
            try:
                boost_int = int(boost)
            except (TypeError, ValueError):
                continue
            if not 0 <= boost_int <= 5:
                continue
            ENV_BOOST[env.lower()] = max(ENV_BOOST.get(env.lower(), 0), boost_int)
            added[env.lower()] = ENV_BOOST[env.lower()]
    if added:
        logger.info("Custom scoring boosts loaded: %s", added)
    return added


def get_environment_boost() -> dict[str, int]:
    return dict(ENV_BOOST)
