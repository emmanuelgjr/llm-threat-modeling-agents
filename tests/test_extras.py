"""Tests for the new exporters, scoring, cache, config, init and webhook."""

import csv
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from main import run_pipeline
from utils import scoring
from utils.cache import compute_cache_key, read_cache, write_cache
from utils.config import load_defaults
from utils.csv_export import CSV_HEADERS, write_csv
from utils.init_project import init_project
from utils.pdf import PDFUnavailableError, write_pdf
from utils.scoring import load_scoring_plugins
from utils.webhook import _build_payload, notify

SCENARIO = {
    "name": "Customer Service GenAI Bot",
    "description": "A customer support chatbot that can access sensitive customer data via tool calls.",
    "environment": "SaaS, Cloud",
}


# ---- CSV -------------------------------------------------------------------

def test_csv_export(tmp_path):
    results = run_pipeline([SCENARIO])
    out = tmp_path / "report.csv"
    rows = write_csv(results, str(out))
    assert rows == sum(len(r["risks"]) for r in results)
    with open(out, encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert header == CSV_HEADERS
        body = list(reader)
    assert body
    assert all(len(row) == len(CSV_HEADERS) for row in body)


# ---- PDF -------------------------------------------------------------------

def test_pdf_falls_back_with_helpful_error(tmp_path, monkeypatch):
    # Force the optional import to fail.
    import utils.pdf as pdf_mod

    def boom():
        raise PDFUnavailableError("forced for test")

    monkeypatch.setattr(pdf_mod, "_import_weasyprint", boom)
    with pytest.raises(PDFUnavailableError):
        write_pdf([], str(tmp_path / "report.pdf"))


# ---- Cache -----------------------------------------------------------------

def test_cache_round_trip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    input_path = tmp_path / "in.json"
    input_path.write_text(json.dumps({"scenarios": [SCENARIO]}), encoding="utf-8")
    key = compute_cache_key(str(input_path), [])
    assert read_cache(key) is None
    write_cache(key, [{"hello": "world"}])
    assert read_cache(key) == [{"hello": "world"}]
    # Different inputs -> different keys
    input_path.write_text(json.dumps({"scenarios": [SCENARIO, SCENARIO]}), encoding="utf-8")
    assert compute_cache_key(str(input_path), []) != key


# ---- Config ----------------------------------------------------------------

def test_load_defaults_reads_toml(tmp_path):
    cfg = tmp_path / "threat-model.toml"
    cfg.write_text('[defaults]\ninput = "x.json"\nfail_on = "high"\n', encoding="utf-8")
    defaults = load_defaults(str(cfg))
    assert defaults.get("input") == "x.json"
    assert defaults.get("fail_on") == "high"


def test_load_defaults_missing_returns_empty(tmp_path):
    assert load_defaults(str(tmp_path / "nope.toml")) == {}


# ---- Scoring plugin --------------------------------------------------------

def test_scoring_plugin_extends_boost(tmp_path):
    scoring.reset()
    plugin = tmp_path / "score.json"
    plugin.write_text(
        json.dumps({"scoring": {"environment_boost": {"iot": 2, "edge": 1}}}),
        encoding="utf-8",
    )
    added = load_scoring_plugins([str(plugin)])
    assert added == {"iot": 2, "edge": 1}
    assert scoring.get_environment_boost()["iot"] == 2
    scoring.reset()


# ---- Init scaffold ---------------------------------------------------------

def test_init_creates_files(tmp_path):
    created = init_project(str(tmp_path))
    paths = {Path(p).name for p in created}
    assert {"sample_inputs.json", "example.json", "threat-model.toml"} <= paths
    assert (tmp_path / "data" / "plugins" / "example.json").exists()
    # Re-running is a no-op
    again = init_project(str(tmp_path))
    assert again == []


# ---- Webhook ---------------------------------------------------------------

def test_webhook_payload_filters_by_threshold():
    results = run_pipeline([SCENARIO])
    payload = _build_payload(results, "Critical")
    assert payload["summary"]["threshold"] == "Critical"
    assert "LLM Threat Modeling" in payload["text"]


def test_webhook_skips_when_no_matching_risks():
    fake_results = [{"scenario": {"name": "x"}, "risks": [{"severity": "Low", "threat": "t", "risk_score": 1}]}]
    with patch("utils.webhook.urlopen") as fake_url:
        sent = notify(fake_results, "https://example.invalid/hook", threshold="Critical")
    assert sent is False
    fake_url.assert_not_called()


def test_webhook_posts_when_match(monkeypatch):
    results = [
        {
            "scenario": {"name": "x"},
            "risks": [{"severity": "Critical", "threat": "Tool Misuse", "risk_score": 25}],
        }
    ]
    captured = {}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout=10.0):
        captured["data"] = req.data
        return FakeResp()

    monkeypatch.setattr("utils.webhook.urlopen", fake_urlopen)
    sent = notify(results, "https://example.invalid/hook", threshold="Critical")
    assert sent is True
    body = json.loads(captured["data"].decode("utf-8"))
    assert body["summary"]["threshold"] == "Critical"
