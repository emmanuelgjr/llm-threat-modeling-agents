"""Run cache: skip the pipeline when input + plugin set is unchanged.

We hash the input file plus all plugin files. If a previous run with the
same hash is on disk, we return its results JSON instead of re-running.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import time
from typing import Iterable, Optional

from utils.plugins import discover_plugin_files

logger = logging.getLogger(__name__)

DEFAULT_DIR = os.path.join(".cache", "runs")


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_cache_key(input_path: str, plugin_sources: Iterable[str]) -> str:
    h = hashlib.sha256()
    h.update(b"input:")
    h.update(_hash_file(input_path).encode())
    files: list[str] = []
    for source in plugin_sources or []:
        if os.path.isdir(source):
            files.extend(discover_plugin_files(source))
        elif os.path.isfile(source):
            files.append(source)
    for path in sorted(files):
        h.update(b"|plugin:")
        h.update(path.encode())
        h.update(b":")
        h.update(_hash_file(path).encode())
    return h.hexdigest()


def cache_path(key: str, directory: str = DEFAULT_DIR) -> str:
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, f"{key}.json")


def read_cache(key: str, directory: str = DEFAULT_DIR, max_age_seconds: Optional[float] = None):
    path = cache_path(key, directory)
    if not os.path.exists(path):
        return None
    if max_age_seconds is not None:
        age = time.time() - os.path.getmtime(path)
        if age > max_age_seconds:
            logger.info("Cache expired (age %.0fs > ttl %.0fs)", age, max_age_seconds)
            return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def clear_cache(directory: str = DEFAULT_DIR) -> int:
    """Remove all cached run results. Returns the number of files deleted."""
    if not os.path.isdir(directory):
        return 0
    count = 0
    for entry in os.listdir(directory):
        if entry.endswith(".json"):
            try:
                os.remove(os.path.join(directory, entry))
                count += 1
            except OSError:
                pass
    return count


def write_cache(key: str, results, directory: str = DEFAULT_DIR) -> None:
    path = cache_path(key, directory)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f)
    except OSError as exc:
        logger.warning("Could not write run cache %s: %s", path, exc)
