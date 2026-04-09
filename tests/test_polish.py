"""Tests for the optional-polish batch: explain, cache TTL/clear, live NVD."""

import os
import time

import pytest

from utils.cache import clear_cache, read_cache, write_cache
from utils.explain import explain


# ---- Explain ---------------------------------------------------------------

def test_explain_known_threat():
    text = explain("Tool Misuse")
    assert "COMPASS Threat: Tool Misuse" in text
    assert "Mitigation:" in text
    assert "CWE-" in text


def test_explain_known_layer():
    text = explain("Memory")
    assert "MAESTRO Layer: Memory" in text
    assert "Indicators" in text


def test_explain_unknown_suggests():
    text = explain("Tool Misus")  # missing letter
    assert "No threat or layer" in text
    assert "Tool Misuse" in text  # close-match suggestion


# ---- Cache TTL + clear -----------------------------------------------------

def test_cache_ttl_expires(tmp_path):
    directory = str(tmp_path / "runs")
    write_cache("k", [{"a": 1}], directory=directory)
    # Force the file's mtime into the past
    path = os.path.join(directory, "k.json")
    old = time.time() - 3600
    os.utime(path, (old, old))
    assert read_cache("k", directory=directory, max_age_seconds=10) is None
    assert read_cache("k", directory=directory, max_age_seconds=7200) == [{"a": 1}]


def test_clear_cache(tmp_path):
    directory = str(tmp_path / "runs")
    write_cache("a", [1], directory=directory)
    write_cache("b", [2], directory=directory)
    assert clear_cache(directory=directory) == 2
    assert clear_cache(directory=directory) == 0


# ---- Live NVD (gated) ------------------------------------------------------

@pytest.mark.live_nvd
def test_live_nvd_returns_real_cves(tmp_path):
    if not os.getenv("RUN_LIVE_NVD"):
        pytest.skip("set RUN_LIVE_NVD=1 to run live NVD test")
    from utils.nvd import NVDClient

    client = NVDClient(cache_dir=str(tmp_path / "cache"), max_per_cwe=2)
    cves = client.fetch_for_cwe("CWE-79")
    assert isinstance(cves, list)
    if cves:
        assert all("id" in c and c["id"].startswith("CVE-") for c in cves)
